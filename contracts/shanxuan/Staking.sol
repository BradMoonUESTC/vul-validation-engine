// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/Ownable.sol";
import {Pausable} from "@openzeppelin/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/SafeERC20.sol";
import {IERC20} from "@openzeppelin/interfaces/IERC20.sol";
import {IEsHEU} from "./interfaces/IEsHEU.sol";
import {IStaking} from "./interfaces/IStaking.sol";

/// @title Staking
/// @notice Staking contract.
contract Staking is IStaking, Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IEsHEU;
    using SafeERC20 for IERC20;

    /// CONSTANTS ///

    /// @notice Escrowed HEU token address.
    IEsHEU public immutable esHEU;

    /// STORAGE ///

    /// @notice Minimum amount of stake for nodes to be activated
    ///         to receive rewards.
    uint256 public minimumStake;

    /// @notice Minimum bribe for reward distribution.
    ///         1e18 is 100%
    uint256 public minimumBribe = 0.1e18;

    /// @notice Miner information for id.
    mapping(bytes32 => MinerInfo) public minerInfo;

    /// @notice Staked information of user for miner id.
    mapping(address => mapping(bytes32 => UserInfo)) public userInfo;

    /// @notice Whether token is distributed as reward or not.
    mapping(address => bool) public isRewardToken;

    /// @notice Array of distributed reward tokens.
    address[] public rewardTokens;

    /// FUNCTIONS ///

    /// @param esHEU_ token address
    constructor(address esHEU_, uint256 minimumStake_) Ownable(msg.sender) {
        if (esHEU_ == address(0)) {
            revert Staking__EsHEUAddressIsInvalid();
        }

        esHEU = IEsHEU(esHEU_);
        minimumStake = minimumStake_;
    }

    /// External Functions ///

    /// @inheritdoc IStaking
    function pause() external override onlyOwner {
        _pause();
    }

    /// @inheritdoc IStaking
    function unpause() external override onlyOwner {
        _unpause();
    }

    /// @inheritdoc IStaking
    function setMinimumStake(uint256 newMinimumStake)
        external
        override
        onlyOwner
    {
        minimumStake = newMinimumStake;

        emit SetMinimumStake(newMinimumStake);
    }

    /// @inheritdoc IStaking
    function setMinimumBribe(uint256 newMinimumBribe)
        external
        override
        onlyOwner
    {
        if (newMinimumBribe > 1e18) {
            revert Staking__BribeExceedsMaximum();
        }

        minimumBribe = newMinimumBribe;

        emit SetMinimumBribe(newMinimumBribe);
    }

    /// @inheritdoc IStaking
    function setBribe(
        bytes12 gpuId,
        uint256 newBribe
    ) external override whenNotPaused {
        if (newBribe > 1e18) {
            revert Staking__BribeExceedsMaximum();
        }

        bytes32 minerId = _getMinerId(msg.sender, gpuId);

        _checkMinerId(minerId);

        minerInfo[minerId].bribe = newBribe;

        emit SetBribe(msg.sender, gpuId, newBribe);
    }

    /// @inheritdoc IStaking
    function register(bytes12 gpuId) external override {
        bytes32 minerId = _getMinerId(msg.sender, gpuId);

        MinerInfo storage miner = minerInfo[minerId];

        if (miner.account != address(0)) {
            revert Staking__MinerIsAlreadyRegistered();
        }

        miner.account = msg.sender;
        miner.gpuId = gpuId;

        emit Register(msg.sender, gpuId);
    }

    /// @inheritdoc IStaking
    function stake(
        bytes32 minerId,
        uint256 amount
    ) external override whenNotPaused nonReentrant {
        _stake(minerId, amount, false);
    }

    /// @inheritdoc IStaking
    function unstake(
        bytes32 minerId,
        uint256 amount
    ) external override whenNotPaused nonReentrant {
        _unstake(minerId, amount, false);
    }

    /// @inheritdoc IStaking
    function restake(
        bytes32 from,
        bytes32 to,
        uint256 amount
    ) external override whenNotPaused nonReentrant {
        _unstake(from, amount, true);
        _stake(to, amount, true);
    }

    /// @inheritdoc IStaking
    function distribute(
        address token,
        bytes32[] calldata minerIds,
        uint256[] calldata amounts
    ) external override onlyOwner nonReentrant {
        uint256 numMinerIds = minerIds.length;
        uint256 totalAmount;
        uint256 amount;
        uint256 bribe;

        for (uint256 i = 0; i < numMinerIds; ++i) {
            MinerInfo storage miner = minerInfo[minerIds[i]];

            if (miner.amount < minimumStake) {
                continue;
            }

            amount = amounts[i];

            bribe = miner.bribe;

            if (bribe < minimumBribe) {
                bribe = minimumBribe;
            }

            uint256 bribeReward = amount * bribe / 1e18;

            miner.reward[token] += (amount - bribeReward);
            miner.bribedReward[token] += bribeReward;
            miner.accTokenPerShare[token] += bribeReward * 1e18 / miner.amount;

            totalAmount += amount;
        }

        if (!isRewardToken[token]) {
            isRewardToken[token] = true;
            rewardTokens.push(token);
        }

        IERC20(token).safeTransferFrom(msg.sender, address(this), totalAmount);

        emit Distribute(token, minerIds, amounts);
    }

    /// @inheritdoc IStaking
    function claimMinerReward(
        bytes12 gpuId,
        address token
    ) external override whenNotPaused nonReentrant {
        bytes32 minerId = _getMinerId(msg.sender, gpuId);
        MinerInfo storage miner = minerInfo[minerId];

        _checkMinerId(minerId);
        _checkRewardToken(token);

        uint256 reward = miner.reward[token];

        if (reward == 0) {
            revert Staking__NotEnoughRewardForMiner(msg.sender, gpuId, token);
        }

        IERC20(token).safeTransfer(msg.sender, reward);
        miner.reward[token] = 0;

        emit ClaimMinerReward(msg.sender, gpuId, token, reward);
    }

    /// @inheritdoc IStaking
    function claimStakerReward(
        bytes32 minerId,
        address token
    ) external override whenNotPaused nonReentrant {
        _checkMinerId(minerId);
        _checkRewardToken(token);

        UserInfo storage user = userInfo[msg.sender][minerId];

        int256 accumulatedToken = int256(
            user.amount * minerInfo[minerId].accTokenPerShare[token] / 1e18
        );
        uint256 reward = uint256(accumulatedToken - user.rewardDebt[token]);

        if (reward == 0) {
            revert Staking__NotEnoughRewardForStaker(
                msg.sender, minerId, token
            );
        }

        user.rewardDebt[token] = accumulatedToken;

        IERC20(token).safeTransfer(msg.sender, reward);

        emit ClaimStakerReward(msg.sender, minerId, token, reward);
    }

    /// @inheritdoc IStaking
    function pendingReward(
        address account,
        bytes32 minerId,
        address token
    ) external view override returns (uint256) {
        _checkMinerId(minerId);
        _checkRewardToken(token);

        UserInfo storage user = userInfo[account][minerId];

        return uint256(
            int256(
                user.amount * minerInfo[minerId].accTokenPerShare[token] / 1e18
            ) - user.rewardDebt[token]
        );
    }

    /// @inheritdoc IStaking
    function minerReward(
        bytes32 minerId,
        address token
    ) external view override returns (uint256) {
        return minerInfo[minerId].reward[token];
    }

    /// @inheritdoc IStaking
    function bribedReward(
        bytes32 minerId,
        address token
    ) external view override returns (uint256) {
        return minerInfo[minerId].bribedReward[token];
    }

    /// @inheritdoc IStaking
    function accTokenPerShare(
        bytes32 minerId,
        address token
    ) external view override returns (uint256) {
        return minerInfo[minerId].accTokenPerShare[token];
    }

    /// Internal Functions ///

    /// @notice Stake esHEU for miner.
    /// @param minerId The miner ID to stake for.
    /// @param amount The amount of esHEU to stake.
    /// @param isRestaking Whether it's restaking or not.
    function _stake(
        bytes32 minerId,
        uint256 amount,
        bool isRestaking
    ) internal {
        _checkMinerId(minerId);

        UserInfo storage user = userInfo[msg.sender][minerId];
        MinerInfo storage miner = minerInfo[minerId];

        uint256 numRewardTokens = rewardTokens.length;
        address token;

        for (uint256 i = 0; i < numRewardTokens; ++i) {
            token = rewardTokens[i];

            user.rewardDebt[token] +=
                int256(amount * miner.accTokenPerShare[token]);
        }

        user.amount += amount;
        miner.amount += amount;

        if (!isRestaking) {
            esHEU.safeTransferFrom(msg.sender, address(this), amount);
        }

        emit Stake(msg.sender, minerId, amount);
    }

    /// @notice Unstake esHEU for miner.
    /// @param minerId The miner ID to unstake.
    /// @param amount The amount of esHEU to unstake.
    /// @param isRestaking Whether it's restaking or not.
    function _unstake(
        bytes32 minerId,
        uint256 amount,
        bool isRestaking
    ) internal {
        UserInfo storage user = userInfo[msg.sender][minerId];
        MinerInfo storage miner = minerInfo[minerId];

        if (user.amount < amount) {
            revert Staking__ExceedsStakedAmount(
                msg.sender, minerId, user.amount
            );
        }

        uint256 numRewardTokens = rewardTokens.length;
        address token;

        for (uint256 i = 0; i < numRewardTokens; ++i) {
            token = rewardTokens[i];

            user.rewardDebt[token] -=
                int256(amount * miner.accTokenPerShare[token] / 1e18);
        }

        user.amount -= amount;
        miner.amount -= amount;

        if (!isRestaking) {
            esHEU.safeTransfer(msg.sender, amount);
        }

        emit Unstake(msg.sender, minerId, amount);
    }

    /// @notice Calculate miner ID from account address and GPU ID
    /// @param account The address of account.
    /// @param gpuId The ID of GPU.
    function _getMinerId(
        address account,
        bytes12 gpuId
    ) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(account))) << 96 | gpuId;
    }

    function _checkMinerId(bytes32 minerId) internal view {
        if (minerInfo[minerId].account == address(0)) {
            revert Staking__MinerIsNotRegistered();
        }
    }

    function _checkRewardToken(address token) internal view {
        if (!isRewardToken[token]) {
            revert Staking__TokenIsNotRewardToken(token);
        }
    }
}
