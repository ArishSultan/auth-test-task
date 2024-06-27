import 'package:ex_trader/src/features/auth/login_screen.dart';
import 'package:ex_trader/src/features/home/home_view.dart';
import 'package:ex_trader/src/navigation/nav.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'src/core/local/secure_storage.dart';
import 'src/widgets/app_snack_bar.dart';

class App extends StatefulWidget {
  const App({super.key});

  static Future<void> initialize() async {
    WidgetsFlutterBinding.ensureInitialized();
    return runApp(
      const ProviderScope(
        child: App(),
      ),
    );
  }

  @override
  State<App> createState() => _AppState();
}

class _AppState extends State<App> {
  final SecureStorage secureStorage = SecureStorage();

  String? accessKey;

  @override
  void initState() {
    getAccessKey();
    super.initState();
  }

  void getAccessKey() async {
    accessKey = await secureStorage.getAccessKey();
    print("Access Key: $accessKey");
    setState(() {});
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: "ExTraders",
      scaffoldMessengerKey: AppSnackBar.snackbarKey,
      navigatorKey: AppNavigation.navigatorKey,
      home: accessKey != null ? const HomeView() : const LoginScreen(),
    );
  }
}
