# Singleton Paymaster

This repository contains an ERC-4337 paymaster implementation that allows users to sponsor their gas fees either with ERC-20 tokens (ERC-20 mode) or with their Pimlico balance (verifying mode).

## Features
- ✅ Users paying with ERC-20 tokens for transaction fees
- ✅ Users paying with Pimlico balance
- ✅ Compatible with EntryPoint v0.7 and v0.6
- ✅ Optional ability to fund sender

## Architecture

This is a permissioned paymaster where the user will have to request sponsorship from Pimlico's API. If sponsorship is granted, the userOperation and all related fields are signed over by a designated signing key, this signature is then checked onchain.

ERC-20 Mode:
- The user (sender) pays for gas with ERC-20 tokens.
- The Pimlico API provides the exchange rate quote.

Verifying Mode:
- The user (sender) pays for gas with their Pimlico balance.
- The user has the option to fund their smart account with their Pimlico balance.
    - The paymaster will fund the user (sender) by calling the EntryPoint's `withdrawTo(address,uint)` method.

**Note:** In ERC-20 mode, the paymaster does not take a prefund during the `validatePaymasterUserOp` phase. This means that a malicious user can bypass the payment phase in the `postOp` call. If a user does this, the userOperation will be funded from their Pimlico balance.

## Core Contracts

| Contract | Description |
|---|---|
| `BasePaymaster`                   | [eth-infinitism's helper class](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/BasePaymaster.sol) for creating paymaster. |
| `BaseSingletonPaymaster`          | Helper class with common functions for V6 and V7 implementations. |
| `SingletonPaymasterV6`            | V6 Singleton paymaster implementation. |
| `SingletonPaymasterV7`            | V7 Singleton paymaster implementation. |


## Coverage

Run the following

```bash
forge coverage --no-match-coverage test/utils
```
