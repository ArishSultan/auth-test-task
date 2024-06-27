import 'package:ex_trader/src/const/images.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_in.dart';
import 'package:ex_trader/src/features/auth/providers/sign_in_provider/sign_in_provider.dart';
import 'package:ex_trader/src/features/auth/signup_screen.dart';
import 'package:ex_trader/src/features/home/home_view.dart';
import 'package:ex_trader/src/navigation/nav.dart';
import 'package:ex_trader/src/utils/compute_action.dart';
import 'package:ex_trader/src/widgets/app_snack_bar.dart';
import 'package:ex_trader/src/widgets/custom_button.dart';
import 'package:ex_trader/src/widgets/custom_textfield.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/svg.dart';
import 'package:reusables/mixins/form_state_mixin.dart';
import 'package:reusables/utils/input_validator.dart';

import '../../core/local/secure_storage.dart';
import '../../shared/states/app_loading_state.dart';
import '../../theme/app_themes.dart';

class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});

  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> with FormStateMixin {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  bool isCheck = false;
  bool isHidden = true;

  final SecureStorage secureStorage = SecureStorage();

  @override
  void dispose() {
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final loading = ref.watch(signInProvider);
    final isLoading = loading == const AppLoadingState.loading();
    final padding = MediaQuery.paddingOf(context);
    return Scaffold(
      backgroundColor: Theme.of(context).appBarTheme.backgroundColor,
      body: SingleChildScrollView(
        padding: EdgeInsets.only(left: 20, right: 20, top: padding.top + 50),
        child: Form(
          key: formKey,
          child: Column(children: [
            Container(
              height: 48,
              width: 48,
              decoration: BoxDecoration(
                image: DecorationImage(
                  image: AssetImage(
                    imageAssets.appIcon,
                  ),
                  fit: BoxFit.fill,
                ),
              ),
            ),
            const SizedBox(height: 20),
            Text(
              "Welcome",
              style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                    fontSize: 24,
                    fontWeight: FontWeight.w800,
                  ),
            ),
            const SizedBox(height: 10),
            Text(
              "Sign in to your account",
              style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                    fontSize: 16,
                    fontWeight: FontWeight.w400,
                    color: HexColor(AppTheme.secondaryColorString!),
                  ),
            ),
            const SizedBox(height: 40),
            CustomTextField(
              hintText: "Email",
              prefix: Padding(
                padding: const EdgeInsets.all(10.0),
                child: SvgPicture.asset(
                  imageAssets.email,
                  colorFilter: ColorFilter.mode(
                    HexColor(AppTheme.secondaryColorString!),
                    BlendMode.srcIn,
                  ),
                ),
              ),
              sufix: const SizedBox(),
              textEditingController: _emailController,
              inputType: TextInputType.emailAddress,
              isObsecure: false,
              validator: InputValidator.multiple([
                InputValidator.required(message: 'Email is required!')!,
                InputValidator.email(message: 'Enter valid email!')!,
              ]),
            ),
            const SizedBox(height: 30),
            CustomTextField(
              hintText: "Password",
              prefix: Padding(
                padding: const EdgeInsets.all(10.0),
                child: SvgPicture.asset(
                  imageAssets.lock,
                  colorFilter: ColorFilter.mode(
                    HexColor(AppTheme.secondaryColorString!),
                    BlendMode.srcIn,
                  ),
                ),
              ),
              sufix: InkWell(
                onTap: () {
                  isHidden = !isHidden;
                  setState(() {});
                },
                child: IconButton(
                  padding: const EdgeInsets.all(10.0),
                  onPressed: () {
                    isHidden = !isHidden;
                    setState(() {});
                  },
                  icon: SvgPicture.asset(
                    imageAssets.eye,
                    colorFilter: ColorFilter.mode(
                      isHidden
                          ? HexColor(AppTheme.secondaryColorString!)
                          : HexColor(AppTheme.primaryColorString!),
                      BlendMode.srcIn,
                    ),
                  ),
                ),
              ),
              textEditingController: _passwordController,
              inputType: TextInputType.emailAddress,
              isObsecure: false,
              validator: InputValidator.multiple([
                InputValidator.required(
                  message: 'Password is required!',
                )!,
                InputValidator.password()!,
              ]),
            ),
            const SizedBox(height: 30),
            CustomButton(
              text: isLoading ? "Wait" : "Sign In",
              onTap: submitter,
            ),
            const SizedBox(height: 30),
            Center(
              child: Text(
                "Forgot password?",
                style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                      fontSize: 16,
                      fontWeight: FontWeight.w800,
                      color: HexColor(AppTheme.primaryColorString!),
                    ),
              ),
            ),
            const SizedBox(height: 20),
            GestureDetector(
              onTap: () {
                AppNavigation.push(const SignupScreen());
              },
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    "Don’t have an account? ",
                    style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                          fontSize: 14,
                          fontWeight: FontWeight.w800,
                          color: HexColor(AppTheme.secondaryColorString!),
                        ),
                  ),
                  Text(
                    "Sign Up",
                    style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                          fontSize: 14,
                          fontWeight: FontWeight.w800,
                          color: HexColor(AppTheme.primaryColorString!),
                        ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 20),
          ]),
        ),
      ),
    );
  }

  @override
  Future<void> onSubmit() async {
    final data = SignInModel(
      email: _emailController.text,
      password: _passwordController.text,
    );
    final result = await performNetworkOperation(
      context,
      () => ref.read(signInProvider.notifier).signIn(data),
    );
    if (result == null) return;
    secureStorage.saveAccessKey(result.accessToken);
    if (!mounted) return;
    AppSnackBar.showSnackbar('Login Success!');
    AppNavigation.pushAndRemoveUntil(const HomeView());
  }
}
