
import 'package:ex_trader/src/const/images.dart';
import 'package:ex_trader/src/widgets/custom_button.dart';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

import '../../theme/app_themes.dart';

class CardView extends StatelessWidget {
  const CardView({super.key});

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.sizeOf(context);

    return Container(
      decoration: BoxDecoration(
        color: AppTheme.isLightTheme == true
            ? HexColor(AppTheme.lightGrayString!)
            : HexColor(AppTheme.darkGrayString!),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Padding(
        padding: const EdgeInsets.all(20.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Text(
                            "Total Balance (USD)",
                            style: Theme.of(context)
                                .textTheme
                                .bodyMedium!
                                .copyWith(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                  color:
                                      HexColor(AppTheme.secondaryColorString!),
                                ),
                          ),
                          const SizedBox(width: 5),
                          SizedBox(
                            height: 16,
                            width: 16,
                            child: SvgPicture.asset(
                              imageAssets.eye,
                              color: HexColor(AppTheme.secondaryColorString!),
                            ),
                          )
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        "1,008,612",
                        style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                              fontSize: 28,
                              fontWeight: FontWeight.w800,
                            ),
                      ),
                    ],
                  ),
                ),
                Expanded(
                  child: Image.asset(
                    imageAssets.h32,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      "Total Profit",
                      style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                            fontSize: 8,
                            fontWeight: FontWeight.w600,
                            color: HexColor(AppTheme.secondaryColorString!),
                          ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      "+93.12%",
                      style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                            color: HexColor(AppTheme.greenColorString!),
                          ),
                    ),
                  ],
                ),
                const SizedBox(width: 10),
                Container(
                  height: 28,
                  width: 1,
                  color:
                      HexColor(AppTheme.secondaryColorString!).withOpacity(0.5),
                ),
                const SizedBox(width: 10),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      "Today Profit",
                      style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                            fontSize: 8,
                            fontWeight: FontWeight.w600,
                            color: HexColor(AppTheme.secondaryColorString!),
                          ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      "-11.52%",
                      style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                            fontSize: 12,
                            fontWeight: FontWeight.w600,
                            color: HexColor(AppTheme.redColorString!),
                          ),
                    ),
                  ],
                ),
                const SizedBox(width: 40),
                Expanded(
                  child: SmallButton(
                    text: "Trade",
                    onTap: () {

                    },
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: SmallButton(
                    text: "Transfer",
                    onTap: () {

                    },
                    bg: HexColor(AppTheme.secondaryColorString!),
                  ),
                ),
              ],
            )
          ],
        ),
      ),
    );
  }

}
