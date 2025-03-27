# Singleton Paymaster

This repository contains an ERC-4337 paymaster implementation that allows users
to sponsor their gas fees either with ERC-20 tokens (ERC-20 mode) or with their
Pimlico balance (verifying mode).

## Features

- ✅ Users paying with ERC-20 tokens for transaction fees
- ✅ Users paying with Pimlico balance
- ✅ Compatible with EntryPoint v0.8 and v0.7 and v0.6
- ✅ Optional ability to fund sender
- ✅ Optional ability to restrict bundling of user operation to a whitelisted
  bundler
- ✅ Has a manager & owner roles, only owners are allowed to withdraw the funds
  from contract / entryPoint

## Paymaster Architecture

This is a permissioned paymaster where the user will have to request sponsorship
from Pimlico's API. If sponsorship is granted, the userOperation and all related
fields are signed over by a designated signing key, this signature is then
checked onchain.

ERC-20 Mode:

- The user (sender) pays for gas with ERC-20 tokens.
- The Pimlico API provides the exchange rate quote.
- Optional ability to have a constant fee
- Optional ability to add a recipient to send unused pre-funds

Verifying Mode:

- The user (sender) pays for gas with their Pimlico balance.

**Note:** In ERC-20 mode, the paymaster does not take a prefund during the
`validatePaymasterUserOp` phase. This means that a malicious user can bypass the
payment in the `postOp` call. If a user does this, the userOperation will be
funded from their Pimlico balance.

## MagicSpendPlusMinusHalf Architecture

`src/MagicSpendPlusMinusHalf.sol` is a simple permissioned implementation of
MagicSpend. Users who have a valid signed WithdrawRequest can call the contracts
`requestWithdraw` method to pull funds from. Before and after fulfilling the
user's withdraw request, the contract will run pre and post calls. These calls
are arbitrary and allow the contract to provide just in time liquidity by doing
things such as swapping to the requested token at time of withdraw.

## Core Contracts

| Contract                 | Description                                                                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BasePaymaster`          | [eth-infinitism's helper class](https://github.com/eth-infinitism/account-abstraction/blob/develop/contracts/core/BasePaymaster.sol) for creating paymaster. |
| `BaseSingletonPaymaster` | Helper class with common functions for V6 and V7 implementations.                                                                                            |
| `SingletonPaymasterV6`   | Singleton paymaster implementation (for EntryPoint v0.6).                                                                                                    |
| `SingletonPaymasterV7`   | Singleton paymaster implementation (for EntryPoint v0.7).                                                                                                    |

## Tests And Coverage

> **Note:** This repo contains two versions of OpenZeppelin Contracts v.5.0.2
> (latest version at the time of writing) and v.4.8.3. The latest version is
> used in all contracts found in `src`, the older version is only used in tests.
> This is because EntryPoint v0.6 has OpenZeppelin@v.4.8.3 as a hard dependency.

Run the following

```bash
forge coverage --no-match-coverage test/utils
```
