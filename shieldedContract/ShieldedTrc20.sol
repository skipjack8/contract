pragma solidity ^0.5.12;
pragma experimental ABIEncoderV2;

import "./SafeMath.sol";
import "./TransferHelper.sol";

contract TokenTRC20 {
    function transfer(address _to, uint256 _value) public returns (bool success);

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success);
}

contract ShieldedTRC20 {
    using SafeMath for uint256;
    using TransferHelper for address;

    uint256 public scalingFactor; // used when decimals of TRC20 token is too large.
    uint256 public leafCount;
    uint256 constant INT64_MAX = 2 ** 63 - 1;
    bytes32 public latestRoot;
    mapping(bytes32 => bytes32) public nullifiers; // store nullifiers of spent commitments
    mapping(bytes32 => bytes32) public roots; // store history root
    mapping(uint256 => bytes32) public tree;
    mapping(bytes32 => bytes32) public noteCommitment;
    mapping(uint256 => bytes32[24]) public encryptedNotes;
    bytes32[33] frontier;
    bytes32[32] zeroes; 
    address owner; 
    TokenTRC20 trc20Token;

    event MintNewLeaf(uint256 position, bytes32 cm, bytes32 cv, bytes32 epk, bytes32[21] c);
    event TransferNewLeaf(uint256 position, bytes32 cm, bytes32 cv, bytes32 epk, bytes32[21] c);
    event BurnNewLeaf(uint256 position, bytes32 cm, bytes32 cv, bytes32 epk, bytes32[21] c);
    event TokenMint(address from, uint256 value);
    event TokenBurn(address to, uint256 value, bytes32[3] ciphertext);
    event NoteSpent(bytes32 nf);

    constructor (address trc20ContractAddress, uint256 scalingFactorExponent) public {
        require(scalingFactorExponent < 77, "The scalingFactorExponent is out of range!");
        scalingFactor = 10 ** scalingFactorExponent;
        owner = msg.sender;
        trc20Token = TokenTRC20(trc20ContractAddress);
        require(approveSelf(), "approveSelf failed!");

        zeroes[0] = bytes32(0x0100000000000000000000000000000000000000000000000000000000000000);
        for (uint32 i = 0; i < 31; i++) {
            zeroes[i+1] = pedersenHash(i, zeroes[i], zeroes[i]);
        }
    }

    function approveSelf() public returns (bool) {
        return address(trc20Token).safeApprove(address(this), uint256(- 1));
    }

    // output: cm, cv, epk, proof
    function mint(uint256 rawValue, bytes32[9] calldata output, bytes32[2] calldata bindingSignature, bytes32[21] calldata c) external {
        address sender = msg.sender;
        // transfer the trc20Token from the sender to this contract
        bool transferResult = address(trc20Token).safeTransferFrom(sender, address(this), rawValue);
        require(transferResult, "safeTransferFrom failed!");

        require(noteCommitment[output[0]] == 0, "Duplicate noteCommitments!");
        uint64 value = rawValueToValue(rawValue);
        bytes32 signHash = sha256(abi.encodePacked(address(this), value, output, c));
        (bytes32[] memory ret) = verifyMintProof(output, bindingSignature, value, signHash, frontier, leafCount);
        uint256 result = uint256(ret[0]);
        require(result == 1, "The proof and signature have not been verified by the contract!");

        uint256 slot = uint256(ret[1]);
        uint256 nodeIndex = leafCount + 2 ** 32 - 1;
        tree[nodeIndex] = output[0];
        if (slot == 0) {
            frontier[0] = output[0];
        }
        for (uint256 i = 1; i < slot + 1; i++) {
            nodeIndex = (nodeIndex - 1) / 2;
            tree[nodeIndex] = ret[i + 1];
            if (i == slot) {
                frontier[slot] = tree[nodeIndex];
            }
        }
        latestRoot = ret[slot + 2];
        roots[latestRoot] = latestRoot;
        noteCommitment[output[0]] = output[0];
        
        for(uint256 i = 0; i < 3; i++) {
            encryptedNotes[leafCount][i] = output[i];  
        }
        for(uint256 i = 3; i < 24; i++) {
            encryptedNotes[leafCount][i] = c[i-3];  
        }
        leafCount ++;
        
        emit MintNewLeaf(leafCount - 1, output[0], output[1], output[2], c);
        emit TokenMint(sender, rawValue);
    }
    //input: nf, anchor, cv, rk, proof
    //output: cm, cv, epk, proof
    function transfer(bytes32[10][] calldata input, bytes32[2][] calldata spendAuthoritySignature, bytes32[9][] calldata output, bytes32[2] calldata bindingSignature, bytes32[21][] calldata c) external {
        require(input.length >= 1 && input.length <= 2, "Input number must be 1 or 2!");
        require(input.length == spendAuthoritySignature.length, "Input number must be equal to spendAuthoritySignature number!");
        require(output.length >= 1 && output.length <= 2, "Output number must be 1 or 2!");
        require(output.length == c.length, "Output number must be equal to c number!");

        for (uint256 i = 0; i < input.length; i++) {
            require(nullifiers[input[i][0]] == 0, "The note has already been spent!");
            require(roots[input[i][1]] != 0, "The anchor must exist!");
        }
        for (uint256 i = 0; i < output.length; i++) {
            require(noteCommitment[output[i][0]] == 0, "Duplicate noteCommitment!");
        }

        bytes32 signHash = sha256(abi.encodePacked(address(this), input, output, c));
        (bytes32[] memory ret) = verifyTransferProof(input, spendAuthoritySignature, output, bindingSignature, signHash, 0, frontier, leafCount);
        uint256 result = uint256(ret[0]);
        require(result == 1, "The proof and signature have not been verified by the contract!");

        uint256 offset = 1;
        //ret offset
        for (uint256 i = 0; i < output.length; i++) {
            uint256 slot = uint256(ret[offset++]);
            uint256 nodeIndex = leafCount + 2 ** 32 - 1;
            tree[nodeIndex] = output[i][0];
            if (slot == 0) {
                frontier[0] = output[i][0];
            }
            for (uint256 k = 1; k < slot + 1; k++) {
                nodeIndex = (nodeIndex - 1) / 2;
                tree[nodeIndex] = ret[offset++];
                if (k == slot) {
                    frontier[slot] = tree[nodeIndex];
                }
            }
            leafCount++;
        }
        latestRoot = ret[offset];
        roots[latestRoot] = latestRoot;
        for (uint256 i = 0; i < input.length; i++) {
            bytes32 nf = input[i][0];
            nullifiers[nf] = nf;
            emit NoteSpent(nf);
        }
        for (uint256 i = 0; i < output.length; i++) {
            noteCommitment[output[i][0]] = output[i][0];
            uint256 j = leafCount - (output.length - i);
            for(uint256 k = 0; k < 3; k++) {
                encryptedNotes[j][k] = output[i][k];  
            }
            for(uint256 k = 3; k < 24; k++) {
                encryptedNotes[j][k] = c[i][k-3];  
            }
            emit TransferNewLeaf(j, output[i][0], output[i][1], output[i][2], c[i]);
        }
    }
    //input: nf, anchor, cv, rk, proof
    //output: cm, cv, epk, proof
    function burn(bytes32[10] calldata input, bytes32[2] calldata spendAuthoritySignature, uint256 rawValue, bytes32[2] calldata bindingSignature, address payTo, bytes32[3] calldata burnCipher, bytes32[9][] calldata output, bytes32[21][] calldata c) external {
        uint64 value = rawValueToValue(rawValue);
        bytes32 signHash = sha256(abi.encodePacked(address(this), input, output, c, payTo, value));

        bytes32 nf = input[0];
        bytes32 anchor = input[1];
        require(nullifiers[nf] == 0, "The note has already been spent!");
        require(roots[anchor] != 0, "The anchor must exist!");

        require(output.length <= 1, "Output number cannot exceed 1!");
        require(output.length == c.length, "Output number must be equal to length of c!");

        // bytes32 signHash = sha256(abi.encodePacked(address(this), input, payTo, value, output, c));
        if (output.length == 0) {
            (bool result) = verifyBurnProof(input, spendAuthoritySignature, value, bindingSignature, signHash);
            require(result, "The proof and signature have not been verified by the contract!");
        } else {
            transferInBurn(input, spendAuthoritySignature, value, bindingSignature, signHash, output, c);
        }

        nullifiers[nf] = nf;
        emit NoteSpent(nf);
        //Finally, transfer trc20Token from this contract to the nominated address
        bool transferResult = address(trc20Token).safeTransferFrom(address(this), payTo, rawValue);
        require(transferResult, "safeTransferFrom failed!");

        emit TokenBurn(payTo, rawValue, burnCipher);
    }

    function transferInBurn(bytes32[10] memory input, bytes32[2] memory spendAuthoritySignature, uint64 value, bytes32[2] memory bindingSignature, bytes32 signHash, bytes32[9][] memory output, bytes32[21][] memory c) private {
        bytes32 cm = output[0][0];
        require(noteCommitment[cm] == 0, "Duplicate noteCommitment!");
        bytes32[10][] memory inputs = new bytes32[10][](1);
        inputs[0] = input;
        bytes32[2][] memory spendAuthoritySignatures = new bytes32[2][](1);
        spendAuthoritySignatures[0] = spendAuthoritySignature;
        (bytes32[] memory ret) = verifyTransferProof(inputs, spendAuthoritySignatures, output, bindingSignature, signHash, value, frontier, leafCount);
        uint256 result = uint256(ret[0]);
        require(result == 1, "The proof and signature have not been verified by the contract!");

        uint256 slot = uint256(ret[1]);
        uint256 nodeIndex = leafCount + 2 ** 32 - 1;
        tree[nodeIndex] = cm;
        if (slot == 0) {
            frontier[0] = cm;
        }
        for (uint256 i = 1; i < slot + 1; i++) {
            nodeIndex = (nodeIndex - 1) / 2;
            tree[nodeIndex] = ret[i + 1];
            if (i == slot) {
                frontier[slot] = tree[nodeIndex];
            }
        }
        latestRoot = ret[slot + 2];
        roots[latestRoot] = latestRoot;
        noteCommitment[cm] = cm;
        
        for(uint256 i = 0; i < 3; i++) {
            encryptedNotes[leafCount][i] = output[0][i];  
        }
        for(uint256 i = 3; i < 24; i++) {
            encryptedNotes[leafCount][i] = c[0][i-3];  
        }
        leafCount ++;

        emit BurnNewLeaf(leafCount - 1, cm, output[0][1], output[0][2], c[0]);
    }

    //position: index of leafnode, start from 0
    function getPath(uint256 position) public view returns (bytes32, bytes32[32] memory) {
        require(position >= 0, "Position should be non-negative!");
        require(position < leafCount, "Position should be smaller than leafCount!");
        uint256 index = position + 2 ** 32 - 1;
        bytes32[32] memory path;
        uint32 level = ancestorLevel(position);
        bytes32 targetNodeValue = getTargetNodeValue(position, level);
        for (uint32 i = 0; i < 32; i++) {
            if (i == level) {
                path[31 - i] = targetNodeValue;
            } else {
                if (index % 2 == 0) {
                    path[31 - i] = tree[index - 1];
                } else {
                    path[31 - i] = tree[index + 1] == 0 ? zeroes[i] : tree[index + 1];
                }
            }
            index = (index - 1) / 2;
        }
        return (latestRoot, path);
    }

    function ancestorLevel(uint256 leafIndex) private view returns (uint32) {
        uint256 nodeIndex1 = leafIndex + 2 ** 32 - 1;
        uint256 nodeIndex2 = leafCount + 2 ** 32 - 2;
        uint32 level = 0;
        while (((nodeIndex1 - 1) / 2) != ((nodeIndex2 - 1) / 2)) {
            nodeIndex1 = (nodeIndex1 - 1) / 2;
            nodeIndex2 = (nodeIndex2 - 1) / 2;
            level = level + 1;
        }
        return level;
    }

    function getTargetNodeValue(uint256 leafIndex, uint32 level) private view returns (bytes32) {
        bytes32 left;
        bytes32 right;
        uint256 index = leafIndex + 2 ** 32 - 1;
        uint256 nodeIndex = leafCount + 2 ** 32 - 2;
        bytes32 nodeValue = tree[nodeIndex];
        if (level == 0) {
            if (index < nodeIndex) {
                return nodeValue;
            }
            if (index == nodeIndex) {
                if (index % 2 == 0) {
                    return tree[index - 1];
                } else {
                    return zeroes[0];
                }
            }
        }
        for (uint32 i = 0; i < level; i++) {
            if (nodeIndex % 2 == 0) {
                left = tree[nodeIndex - 1];
                right = nodeValue;
            } else {
                left = nodeValue;
                right = zeroes[i];
            }
            nodeValue = pedersenHash(i, left, right);
            nodeIndex = (nodeIndex - 1) / 2;
        }
        return nodeValue;
    }

    function rawValueToValue(uint256 rawValue) private view returns (uint64) {
        require(rawValue > 0, "Value must be positive!");
        require(rawValue.mod(scalingFactor) == 0, "Value must be integer multiples of scalingFactor!");
        uint256 value = rawValue.div(scalingFactor);
        require(value < INT64_MAX);
        return uint64(value);
    }
}