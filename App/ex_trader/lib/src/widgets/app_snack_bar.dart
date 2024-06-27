import 'package:ex_trader/src/const/fonts.dart';
import 'package:ex_trader/src/theme/colors.dart';
import 'package:flutter/material.dart';


sealed class AppSnackBar {
  static final snackbarKey = GlobalKey<ScaffoldMessengerState>();

  static void showSnackbar(String text) {
    final messenger = snackbarKey.currentState;
    messenger?.removeCurrentSnackBar();
    messenger?.hideCurrentSnackBar();
    messenger?.showSnackBar(
      SnackBar(
        content: Text(
          text,
          style: TextStyle(
            color: Colors.white,
            fontWeight: AppFontWeight.extraBold,
          ),

        ),
        backgroundColor: AppColors.primaryColor,
      ),
    );
  }

  static void showErrorSnackBar(
      [String text = 'Something went wrong. Please try again.']) {
    final messenger = snackbarKey.currentState;
    messenger?.removeCurrentSnackBar();
    messenger?.hideCurrentSnackBar();
    messenger?.showSnackBar(
      SnackBar(
        content: Text(
          text,
          style: const TextStyle(
            color: Colors.white,
          ),

        ),
        backgroundColor: AppColors.red,
      ),
    );
  }
}
