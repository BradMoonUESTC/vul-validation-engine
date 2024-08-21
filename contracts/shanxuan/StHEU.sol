// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ERC20} from "@openzeppelin/ERC20.sol";
import {Ownable} from "@openzeppelin/Ownable.sol";
import {Pausable} from "@openzeppelin/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/SafeERC20.sol";
import {IHEU} from "./interfaces/IHEU.sol";
import {IStHEU} from "./interfaces/IStHEU.sol";

/// @title StHEU
/// @notice Staked HEU token contract.
contract StHEU is IStHEU, ERC20, Ownable, Pausable, ReentrancyGuard {
    using SafeERC20 for IHEU;

    /// CONSTANTS ///

    /// @notice HEU token address.
    IHEU public immutable heu;

    /// STORAGE ///

    /// @notice Whether it's in migration mode or not.
    bool public migrationMode = false;

    /// @notice Vest period.
    uint256 public vestPeriod = 30 days;

    /// @notice Vest information of user for vest id.
    mapping(address => mapping(uint256 => VestInfo)) public vestInfo;

    /// @notice The number of vests of user.
    mapping(address => uint256) public vestCount;

    /// @param heu_ token address
    constructor(address heu_)
        ERC20("Staked Heurist", "stHEU")
        Ownable(msg.sender)
    {
        if (heu_ == address(0)) {
            revert StHEU__HEUAddressIsInvalid();
        }

        heu = IHEU(heu_);
    }

    /// External Functions ///

    /// @inheritdoc IStHEU
    function pause() external override onlyOwner {
        _pause();
    }

    /// @inheritdoc IStHEU
    function unpause() external override onlyOwner {
        _unpause();
    }

    /// @inheritdoc IStHEU
    function setMigrationMode(bool status) external override onlyOwner {
        migrationMode = status;

        emit SetMigrationMode(status);
    }

    /// @inheritdoc IStHEU
    function setVestPeriod(uint256 newPeriod) external override onlyOwner {
        if (newPeriod == 0) {
            revert StHEU__VestPeriodIsInvalid();
        }

        vestPeriod = newPeriod;

        emit SetVestPeriod(newPeriod);
    }

    /// @inheritdoc IStHEU
    function donate(uint256 amount) external override onlyOwner {
        heu.safeTransferFrom(msg.sender, address(this), amount);

        emit Donate(amount);
    }

    /// @inheritdoc IStHEU
    function lock(uint256 amount)
        external
        override
        whenNotPaused
        nonReentrant
    {
        if (migrationMode) {
            revert StHEU__CanNotLockInMigrationMode();
        }
        if (amount == 0) {
            revert StHEU__LockAmountIsInvalid();
        }

        uint256 mintAmount = amount * 1e18 / _exchangeRate();

        heu.safeTransferFrom(msg.sender, address(this), amount);
        _mint(msg.sender, mintAmount);

        emit Lock(amount, mintAmount);
    }

    /// @inheritdoc IStHEU
    function vest(uint256 amount)
        external
        override
        whenNotPaused
        nonReentrant
        returns (uint256 id)
    {
        if (amount == 0) {
            revert StHEU__VestAmountIsInvalid();
        }

        id = vestCount[msg.sender];
        uint256 period = migrationMode ? 0 : vestPeriod;

        vestInfo[msg.sender][id] = VestInfo(amount, block.timestamp + period);
        vestCount[msg.sender] = id + 1;

        _transfer(msg.sender, address(this), amount);

        emit Vest(id, amount, period);
    }

    /// @inheritdoc IStHEU
    function cancelVest(uint256 id)
        external
        override
        whenNotPaused
        nonReentrant
    {
        uint256 amount = vestInfo[msg.sender][id].amount;

        if (amount == 0) {
            revert StHEU__NoVestForId();
        }

        _transfer(address(this), msg.sender, amount);

        delete vestInfo[msg.sender][id];

        emit CancelVest(id, amount);
    }

    /// @inheritdoc IStHEU
    function claim(uint256 id)
        external
        override
        whenNotPaused
        nonReentrant
        returns (uint256 heuAmount)
    {
        uint256 amount;

        (amount, heuAmount) = _calcClaimAmount(id);

        delete vestInfo[msg.sender][id];

        heu.safeTransfer(msg.sender, heuAmount);
        _burn(address(this), amount);

        emit Claim(id, heuAmount);
    }

    /// @inheritdoc IStHEU
    function claimableAmount(uint256 id)
        external
        view
        override
        returns (uint256 heuAmount)
    {
        (, heuAmount) = _calcClaimAmount(id);
    }

    /// @inheritdoc IStHEU
    function exchangeRate() external view override returns (uint256) {
        return _exchangeRate();
    }

    /// Internal Functions ///

    /// @notice Return estimated amount of HEU token for claim.
    /// @param id The id of the vesting.
    /// @return amount The burn amount of stHEU.
    /// @return heuAmount The estimated amount of HEU.
    function _calcClaimAmount(uint256 id)
        internal
        view
        returns (uint256 amount, uint256 heuAmount)
    {
        VestInfo storage info = vestInfo[msg.sender][id];

        amount = info.amount;

        if (amount == 0) {
            revert StHEU__NoVestForId();
        }
        if (block.timestamp < info.end && !migrationMode) {
            revert StHEU__CanNotClaimEarlier();
        }

        heuAmount = amount * _exchangeRate() / 1e18;
    }

    /// @notice Returns exchange rate between HEU and stHEU.
    /// @return Exchange rate between HEU and stHEU.
    function _exchangeRate() internal view returns (uint256) {
        uint256 totalHEU = heu.balanceOf(address(this));
        uint256 totalSupply = totalSupply();

        if (totalHEU == 0 || totalSupply == 0) {
            return 1e18;
        }

        return totalHEU * 1e18 / totalSupply;
    }
}
