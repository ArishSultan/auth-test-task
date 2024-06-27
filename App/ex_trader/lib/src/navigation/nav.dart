import 'package:flutter/material.dart';

class AppNavigation {
  static final navigatorKey = GlobalKey<NavigatorState>();

  static bool canPop() => navigatorKey.currentState!.canPop();

  static Future<dynamic> push(Widget page) async {
    return await navigatorKey.currentState?.push(
      MaterialPageRoute(builder: (context) => page),
    );
  }

  static Future<dynamic> pushReplacement(Widget page) async {
    return await navigatorKey.currentState!.pushReplacement(
      MaterialPageRoute(builder: (context) => page),
    );
  }

  static Future<dynamic> pushAndRemoveUntil(Widget page) async {
    return await navigatorKey.currentState!.pushAndRemoveUntil(
      MaterialPageRoute(builder: (context) => page),
      (route) => false,
    );
  }

  static void popAll() {
    return navigatorKey.currentState!.popUntil((route) => false);
  }

  static void pop([dynamic data]) {
    navigatorKey.currentState!.pop(data);
  }
}
