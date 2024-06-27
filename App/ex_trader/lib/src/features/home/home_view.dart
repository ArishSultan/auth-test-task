// ignore_for_file: deprecated_member_use

import 'package:ex_trader/src/const/images.dart';
import 'package:ex_trader/src/core/local/secure_storage.dart';
import 'package:ex_trader/src/features/auth/login_screen.dart';
import 'package:ex_trader/src/navigation/nav.dart';
import 'package:ex_trader/src/theme/app_themes.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_svg/flutter_svg.dart';

import 'card.dart';

class HomeView extends StatefulWidget {
  const HomeView({super.key});

  @override
  State<HomeView> createState() => _HomeViewState();
}

class _HomeViewState extends State<HomeView> {



  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(height: MediaQuery.of(context).padding.top + 15),
          Padding(
            padding: const EdgeInsets.only(left: 20, right: 20),
            child: Row(
              children: [
                TextButton(
                    onPressed: () {
                      const FlutterSecureStorage().deleteAll();
                      AppNavigation.pushAndRemoveUntil(const LoginScreen());
                    },
                    child: const Text(
                      "Logout",
                      style: TextStyle(color: Colors.red),
                    )),
                const Spacer(),
                GestureDetector(
                  onTap: () {
                    // Get.dialog(
                    //   const ScanScreen(),
                    // );
                  },
                  child: SizedBox(
                    height: 24,
                    width: 24,
                    child: SvgPicture.asset(
                      imageAssets.h24,
                      colorFilter: ColorFilter.mode(
                        Theme.of(context).textTheme.bodyLarge!.color!,
                        BlendMode.srcIn,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 20),
                InkWell(
                  onTap: () {},
                  child: SizedBox(
                    height: 24,
                    width: 24,
                    child: SvgPicture.asset(
                      AppTheme.isLightTheme == true
                          ? imageAssets.h5
                          : imageAssets.m8,
                    ),
                  ),
                )
              ],
            ),
          ),
          Expanded(
            child: ListView(
              padding: EdgeInsets.zero,
              physics: const ClampingScrollPhysics(),
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const SizedBox(height: 30),
                    Padding(
                      padding: const EdgeInsets.only(left: 20, right: 20),
                      child: Text(
                        "Portfolio Value",
                        style: Theme.of(context).textTheme.bodyLarge!.copyWith(
                              fontSize: 16,
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ),
                    const SizedBox(height: 15),
                    const Padding(
                      padding: EdgeInsets.only(left: 20, right: 20),
                      child: CardView(),
                    ),
                    const SizedBox(height: 25),
                    Padding(
                      padding: const EdgeInsets.only(left: 20, right: 20),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceBetween,
                        children: [
                          Text(
                            "Quick Buy",
                            style:
                                Theme.of(context).textTheme.bodyLarge!.copyWith(
                                      fontSize: 16,
                                      fontWeight: FontWeight.w800,
                                    ),
                          ),
                          Text(
                            "View all",
                            style: Theme.of(context)
                                .textTheme
                                .bodyLarge!
                                .copyWith(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w600,
                                  color:
                                      HexColor(AppTheme.secondaryColorString!),
                                ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(height: 15),
                    SizedBox(
                      height: 72,
                      child: ListView.builder(
                        itemCount: 5,
                        padding: const EdgeInsets.only(left: 20, right: 20),
                        scrollDirection: Axis.horizontal,
                        itemBuilder: (BuildContext context, int index) {
                          return InkWell(
                            onTap: () {},
                            child: Padding(
                              padding: const EdgeInsets.only(right: 14),
                              child: Container(
                                height: 72,
                                width: 72,
                                decoration: BoxDecoration(
                                  borderRadius: BorderRadius.circular(14),
                                  color: AppTheme.isLightTheme == true
                                      ? HexColor(AppTheme.lightGrayString!)
                                      : HexColor(AppTheme.darkGrayString!),
                                ),
                                child: Padding(
                                  padding: const EdgeInsets.all(16.0),
                                  child: Image.asset(
                                    index == 0
                                        ? imageAssets.h15
                                        : index == 1
                                            ? imageAssets.h19
                                            : index == 2
                                                ? imageAssets.h18
                                                : index == 3
                                                    ? imageAssets.h25
                                                    : imageAssets.h26,
                                  ),
                                ),
                              ),
                            ),
                          );
                        },
                      ),
                    ),
                    const SizedBox(height: 25),
                    Padding(
                      padding: const EdgeInsets.only(left: 20, right: 20),
                      child: Text(
                        "Watchlist",
                        style: Theme.of(context).textTheme.bodyLarge!.copyWith(
                              fontSize: 16,
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ),
                    // Padding(
                    //   padding:
                    //       const EdgeInsets.only(left: 20, right: 20, top: 15),
                    //   child: Column(
                    //     crossAxisAlignment: CrossAxisAlignment.start,
                    //     children: [
                    //       for (var i = 0; i < 2; i++)
                    //         Padding(
                    //           padding: const EdgeInsets.only(bottom: 15),
                    //           child: CoinView(
                    //             image: i == 0 ? imageAssets.h15 : imageAssets.h19,
                    //             text1: i == 0 ? "Bitcoin" : "Ethereum",
                    //             text2: i == 0 ? "BTC/USd" : "ETH/USD",
                    //             text3: i == 0 ? "40,168.53" : "2744.37",
                    //             text4: i == 0 ? "+2.16%" : "+1.15%",
                    //           ),
                    //         ),
                    //     ],
                    //   ),
                    // ),
                    GestureDetector(
                      onTap: () {
                        // Get.to(
                        //   () => const TopMoveScreen(),
                        //   transition: Transition.rightToLeft,
                        // );
                      },
                      child: Padding(
                        padding: const EdgeInsets.only(left: 20, right: 20),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceBetween,
                          children: [
                            Text(
                              "Top Movers",
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyLarge!
                                  .copyWith(
                                    fontSize: 16,
                                    fontWeight: FontWeight.w800,
                                  ),
                            ),
                            Text(
                              "View all",
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyLarge!
                                  .copyWith(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w600,
                                    color: HexColor(
                                        AppTheme.secondaryColorString!),
                                  ),
                            ),
                          ],
                        ),
                      ),
                    ),
                    const SizedBox(height: 15),
                    SizedBox(
                      height: 150,
                      child: ListView.builder(
                        itemCount: 5,
                        padding: const EdgeInsets.only(left: 20, right: 20),
                        scrollDirection: Axis.horizontal,
                        itemBuilder: (BuildContext context, int index) {
                          return Padding(
                            padding: const EdgeInsets.only(right: 14),
                            child: Container(
                              height: 140,
                              width: 132,
                              decoration: BoxDecoration(
                                borderRadius: BorderRadius.circular(14),
                                color: AppTheme.isLightTheme == true
                                    ? HexColor(AppTheme.lightGrayString!)
                                    : HexColor(AppTheme.darkGrayString!),
                              ),
                              child: Padding(
                                padding: const EdgeInsets.all(16.0),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      mainAxisAlignment:
                                          MainAxisAlignment.spaceBetween,
                                      children: [
                                        SizedBox(
                                          height: 24,
                                          width: 24,
                                          child: Image.asset(
                                            index == 0
                                                ? imageAssets.h20
                                                : index == 1
                                                    ? imageAssets.h25
                                                    : imageAssets.h22,
                                            fit: BoxFit.fill,
                                          ),
                                        ),
                                        SizedBox(
                                          height: 15,
                                          width: 50.45,
                                          child: Image.asset(
                                            imageAssets.h30,
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 15),
                                    Column(
                                      crossAxisAlignment:
                                          CrossAxisAlignment.start,
                                      children: [
                                        Row(
                                          children: [
                                            Text(
                                              index == 0
                                                  ? "FLOW"
                                                  : index == 1
                                                      ? "SAND"
                                                      : "LUNA",
                                              style: Theme.of(context)
                                                  .textTheme
                                                  .bodyLarge!
                                                  .copyWith(
                                                    fontSize: 12,
                                                    fontWeight: FontWeight.w800,
                                                  ),
                                            ),
                                            Text(
                                              "/USD",
                                              style: Theme.of(context)
                                                  .textTheme
                                                  .bodyLarge!
                                                  .copyWith(
                                                    fontSize: 12,
                                                    fontWeight: FontWeight.w400,
                                                    color: HexColor(AppTheme
                                                        .secondaryColorString!),
                                                  ),
                                            ),
                                          ],
                                        ),
                                        const SizedBox(height: 5),
                                        Text(
                                          index == 0
                                              ? "\$5.89"
                                              : index == 1
                                                  ? "\$3.31"
                                                  : "\$101.31",
                                          style: Theme.of(context)
                                              .textTheme
                                              .bodyLarge!
                                              .copyWith(
                                                fontSize: 12,
                                                fontWeight: FontWeight.w500,
                                                color: HexColor(AppTheme
                                                    .secondaryColorString!),
                                              ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 15),
                                    Text(
                                      index == 0
                                          ? "-17.3%"
                                          : index == 1
                                              ? "-5.14%"
                                              : "-2.12%",
                                      style: Theme.of(context)
                                          .textTheme
                                          .bodyLarge!
                                          .copyWith(
                                            fontSize: 16,
                                            fontWeight: FontWeight.w800,
                                            color: HexColor(
                                                AppTheme.redColorString!),
                                          ),
                                    ),
                                  ],
                                ),
                              ),
                            ),
                          );
                        },
                      ),
                    ),
                    const SizedBox(height: 30),
                  ],
                ),
              ],
            ),
          )
        ],
      ),
    );
  }
}
