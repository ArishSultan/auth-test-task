// ignore_for_file: deprecated_member_use

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class AppTheme {
  // static String? primaryColorString = "#4A3EF6";
  static String? primaryColorString = "#007AFF";
  static String? secondaryColorString = "#828A99";
  static String? redColorString = "#FF7171";
  static String? greenColorString = "#39CC77";
  static String? lightGrayString = "#F2F2F7";
  static String? darkGrayString = "#1C222E";
  static bool isLightTheme = true;

  static ThemeData getTheme() {
    if (isLightTheme) {
      return lightTheme();
    } else {
      return darkTheme();
    }
  }

  static TextTheme _buildTextTheme(TextTheme base, Color? color) {
    return base.copyWith(
      titleLarge: GoogleFonts.manrope(
          textStyle: TextStyle(
              color: color, fontSize: 20, fontWeight: FontWeight.w500)),
      titleMedium:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 18)),
      titleSmall: GoogleFonts.manrope(
          textStyle: TextStyle(
              color: color, fontSize: 14, fontWeight: FontWeight.w500)),
      bodyLarge:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 14)),
      bodyMedium:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 16)),
      labelLarge: GoogleFonts.manrope(
          textStyle: TextStyle(
              color: base.labelLarge!.color,
              fontSize: 14,
              fontWeight: FontWeight.w500)),
      bodySmall:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 12)),
      headlineMedium:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 34)),
      displaySmall:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 48)),
      displayMedium:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 60)),
      displayLarge:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 96)),
      headlineSmall:
          GoogleFonts.manrope(textStyle: TextStyle(color: color, fontSize: 24)),
      labelSmall: GoogleFonts.manrope(
          textStyle: TextStyle(color: base.labelSmall!.color, fontSize: 10)),
    );
  }

  static ThemeData lightTheme() {
    Color primaryColor = HexColor(primaryColorString!);
    Color secondaryColor = HexColor(secondaryColorString!);
    final ColorScheme colorScheme = const ColorScheme.light().copyWith(
      primary: primaryColor,
      secondary: secondaryColor,
    );

    final ThemeData base = ThemeData.light();
    return base.copyWith(
      appBarTheme: const AppBarTheme(color: Colors.white),
      popupMenuTheme: const PopupMenuThemeData(color: Colors.white),
      primaryColor: primaryColor,
      splashColor: Colors.white.withOpacity(0.1),
      hoverColor: Colors.transparent,
      splashFactory: InkRipple.splashFactory,
      highlightColor: Colors.transparent,
      canvasColor: Colors.white,
      scaffoldBackgroundColor: Colors.white,
      cardColor: Colors.red,
      textTheme: _buildTextTheme(base.textTheme, Colors.black),
      primaryTextTheme: _buildTextTheme(base.textTheme, Colors.black),
      platform: TargetPlatform.iOS,
      indicatorColor: primaryColor,
      disabledColor: HexColor("#FFFFFF"),
      iconTheme: const IconThemeData(color: Colors.black), colorScheme: colorScheme.copyWith(background: Colors.white),
    );
  }

  static ThemeData darkTheme() {
    Color primaryColor = HexColor(primaryColorString!);
    Color secondaryColor = HexColor(secondaryColorString!);
    final ColorScheme colorScheme = const ColorScheme.light().copyWith(
      primary: primaryColor,
      secondary: secondaryColor,
    );
    final ThemeData base = ThemeData.dark();
    return base.copyWith(
      popupMenuTheme: PopupMenuThemeData(color: HexColor('#12161F')),
      appBarTheme: AppBarTheme(color: HexColor('#12161F')),
      primaryColor: primaryColor,
      indicatorColor: Colors.white,
      splashColor: Colors.white24,
      splashFactory: InkRipple.splashFactory,
      canvasColor: Colors.white,
      scaffoldBackgroundColor: Colors.grey[850],
      buttonTheme: ButtonThemeData(
        colorScheme: colorScheme,
        textTheme: ButtonTextTheme.primary,
      ),
      textTheme: _buildTextTheme(base.textTheme, Colors.white),
      primaryTextTheme: _buildTextTheme(base.primaryTextTheme, Colors.white),
      platform: TargetPlatform.iOS,
      disabledColor: HexColor('#1C222E'),
      iconTheme: const IconThemeData(color: Colors.white), colorScheme: colorScheme.copyWith(background: Colors.grey[850]),
    );
  }
}

class HexColor extends Color {
  static int _getColorFromHex(String hexColor) {
    hexColor = hexColor.toUpperCase().replaceAll("#", "");
    if (hexColor.length == 6) {
      hexColor = "FF$hexColor";
    }
    return int.parse(hexColor, radix: 16);
  }

  HexColor(final String hexColor) : super(_getColorFromHex(hexColor));
}
