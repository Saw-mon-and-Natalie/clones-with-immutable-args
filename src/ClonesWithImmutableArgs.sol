// SPDX-License-Identifier: BSD

pragma solidity ^0.8.4;

/// @title ClonesWithImmutableArgs
/// @author wighawag, zefram.eth, Saw-mon & Natalie
/// @notice Enables creating clone contracts with immutable args
library ClonesWithImmutableArgs {
    error CreateFail();

    /// @notice Creates a clone proxy of the implementation contract, with immutable args
    /// @dev data cannot exceed 65535 bytes, since 2 bytes are used to store the data length
    /// @param implementation The implementation contract to clone
    /// @param data Encoded immutable args
    /// @return instance The address of the created clone
    function clone(address implementation, bytes memory data)
        internal
        returns (address payable instance)
    {
        // unrealistic for memory ptr or data length to exceed 256 bits
        unchecked {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                let mBefore2 := mload(sub(data, 0x40))
                let mBefore1 := mload(sub(data, 0x20))
                let dataLength := mload(data)
                let dataEnd := add(add(data, 0x20), dataLength)
                let mAfter1 := mload(dataEnd)

                let extraLength := add(dataLength, 2) // +2 bytes for telling how much data there is appended to the call
                let creationSize := add(extraLength, 0x3f)
                let runSize := sub(creationSize, 0x0a)

                // -------------------------------------------------------------------------------------------------------------
                // CREATION (10 bytes)
                // -------------------------------------------------------------------------------------------------------------

                // 61 runtime  | PUSH2 runtime (r)     | r                       | –
                // 3d          | RETURNDATASIZE        | 0 r                     | –
                // 81          | DUP2                  | r 0 r                   | –
                // 60 offset   | PUSH1 offset (o)      | o r 0 r                 | –
                // 3d          | RETURNDATASIZE        | 0 o r 0 r               | –
                // 39          | CODECOPY              | 0 r                     | [0 - runSize): runtime code
                // f3          | RETURN                |                         | [0 - runSize): runtime code

                // -------------------------------------------------------------------------------------------------------------
                // RUNTIME (53 bytes + extraLength)
                // -------------------------------------------------------------------------------------------------------------

                // --- copy calldata to memmory ---
                // 36          | CALLDATASIZE          | cds                     | –
                // 3d          | RETURNDATASIZE        | 0 cds                   | –
                // 3d          | RETURNDATASIZE        | 0 0 cds                 | –
                // 37          | CALLDATACOPY          |                         | [0 - cds): calldata

                // --- keep some values in stack ---
                // 3d          | RETURNDATASIZE        | 0                       | [0 - cds): calldata
                // 3d          | RETURNDATASIZE        | 0 0                     | [0 - cds): calldata
                // 3d          | RETURNDATASIZE        | 0 0 0                   | [0 - cds): calldata
                // 3d          | RETURNDATASIZE        | 0 0 0 0                 | [0 - cds): calldata
                // 61 extra    | PUSH2 extra (e)       | e 0 0 0 0               | [0 - cds): calldata

                // --- copy extra data to memory ---
                // 80          | DUP1                  | e e 0 0 0 0             | [0 - cds): calldata
                // 60 0x35     | PUSH1 0x35            | 0x35 e e 0 0 0 0        | [0 - cds): calldata
                // 36          | CALLDATASIZE          | cds 0x35 e e 0 0 0 0    | [0 - cds): calldata
                // 39          | CODECOPY              | e 0 0 0 0               | [0 - cds): calldata, [cds - cds + e): extraData

                // --- delegate call to the implementation contract ---
                // 36          | CALLDATASIZE          | cds e 0 0 0 0           | [0 - cds): calldata, [cds - cds + e): extraData
                // 01          | ADD                   | cds+e 0 0 0 0           | [0 - cds): calldata, [cds - cds + e): extraData
                // 3d          | RETURNDATASIZE        | 0 cds+e 0 0 0 0         | [0 - cds): calldata, [cds - cds + e): extraData
                // 73 addr     | PUSH20 addr           | addr 0 cds+e 0 0 0 0    | [0 - cds): calldata, [cds - cds + e): extraData
                // 5a          | GAS                   | gas addr 0 cds+e 0 0 0 0| [0 - cds): calldata, [cds - cds + e): extraData
                // f4          | DELEGATECALL          | success 0 0             | [0 - cds): calldata, [cds - cds + e): extraData

                // --- copy return data to memory ---
                // 3d          | RETURNDATASIZE        | rds success 0 0         | [0 - cds): calldata, [cds - cds + e): extraData
                // 3d          | RETURNDATASIZE        | rds rds success 0 0     | [0 - cds): calldata, [cds - cds + e): extraData
                // 93          | SWAP4                 | 0 rds success 0 rds     | [0 - cds): calldata, [cds - cds + e): extraData
                // 80          | DUP1                  | 0 0 rds success 0 rds   | [0 - cds): calldata, [cds - cds + e): extraData
                // 3e          | RETURNDATACOPY        | success 0 rds           | [0 - rds): returndata, ... the rest might be dirty
                
                // 60 0x33     | PUSH1 0x33            | 0x33 success            | [0 - rds): returndata, ... the rest might be dirty
                // 57          | JUMPI                 |                         | [0 - rds): returndata, ... the rest might be dirty

                // --- revert ---
                // fd          | REVERT                |                         | [0 - rds): returndata, ... the rest might be dirty

                // --- return ---
                // 5b          | JUMPDEST              |                         | [0 - rds): returndata, ... the rest might be dirty
                // f3          | RETURN                |                         | [0 - rds): returndata, ... the rest might be dirty

                mstore(
                    data,
                    0x5af43d3d93803e603357fd5bf3
                )

                mstore(
                    sub(data, 0x0d),
                    implementation
                )

                mstore(
                    sub(data, 0x21),
                    or(
                        0x6100003d81600a3d39f3363d3d373d3d3d3d610000806035363936013d73,
                        or(
                            shl(0xd8, runSize),
                            shl(0x48, extraLength)
                        )
                    )
                )
                mstore(dataEnd, shl(0xf0, extraLength))
                instance := create(0, sub(data, 0x1f), creationSize)

                mstore(data, dataLength)
                mstore(sub(data, 0x20), mBefore1)
                mstore(sub(data, 0x40), mBefore2)
                mstore(dataEnd, mAfter1)
            }

            if (instance == address(0)) {
                revert CreateFail();
            }
        }
    }
}
