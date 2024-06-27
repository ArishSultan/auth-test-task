// ignore_for_file: deprecated_member_use

import 'package:ex_trader/src/core/auth/domain/models/sign_up.dart';
import 'package:ex_trader/src/features/auth/providers/sign_up_provider/sign_up_provider.dart';
import 'package:ex_trader/src/features/home/home_view.dart';
import 'package:ex_trader/src/navigation/nav.dart';
import 'package:ex_trader/src/shared/states/app_loading_state.dart';
import 'package:ex_trader/src/utils/compute_action.dart';
import 'package:ex_trader/src/widgets/app_snack_bar.dart';
import 'package:ex_trader/src/widgets/back_icon.dart';
import 'package:ex_trader/src/widgets/custom_button.dart';
import 'package:ex_trader/src/widgets/custom_textfield.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_svg/svg.dart';
import 'package:ex_trader/src/const/images.dart';
import 'package:reusables/mixins/form_state_mixin.dart';
import 'package:reusables/utils/input_validator.dart';
import '../../core/local/secure_storage.dart';
import '../../theme/app_themes.dart';

class SignupScreen extends ConsumerStatefulWidget {
  const SignupScreen({super.key});

  @override
  ConsumerState<SignupScreen> createState() => _SignupScreenState();
}

class _SignupScreenState extends ConsumerState<SignupScreen>
    with FormStateMixin {
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  final _firstNameController = TextEditingController();
  final _lastNameController = TextEditingController();
  bool isCheck = false;
  bool isHidden = true;

  final SecureStorage secureStorage = SecureStorage();

  @override
  Widget build(BuildContext context) {
    final padding = MediaQuery.paddingOf(context);
    final loading = ref.watch(signupProvider);
    bool isLoading = loading == const AppLoadingState.loading();

    return Scaffold(
      backgroundColor: Theme.of(context).appBarTheme.backgroundColor,
      body: SingleChildScrollView(
        padding: EdgeInsets.only(left: 20, right: 20, top: padding.top + 20),
        child: Form(
          key: formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const BackIcon(),
              const SizedBox(height: 50),
              Text(
                "Join CoinSpace",
                style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                    ),
              ),
              const SizedBox(height: 10),
              Row(
                children: [
                  Text(
                    "Create your account. ",
                    style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                          fontSize: 16,
                          fontWeight: FontWeight.w400,
                          color: HexColor(AppTheme.secondaryColorString!),
                        ),
                  ),
                  Text(
                    "Learn more",
                    style: Theme.of(context).textTheme.bodyMedium!.copyWith(
                          fontSize: 16,
                          fontWeight: FontWeight.w400,
                          color: HexColor(AppTheme.primaryColorString!),
                        ),
                  ),
                ],
              ),
              const SizedBox(height: 40),
              CustomTextField(
                hintText: "First Name",
                prefix: Padding(
                  padding: const EdgeInsets.all(10.0),
                  child: SvgPicture.asset(
                    imageAssets.user,
                    color: HexColor(AppTheme.secondaryColorString!),
                  ),
                ),
                sufix: const SizedBox(),
                textEditingController: _firstNameController,
                inputType: TextInputType.name,
                isObsecure: false,
                validator: InputValidator.required(
                    message: 'First Name is required!')!,
              ),
              const SizedBox(height: 30),
              CustomTextField(
                hintText: "Last Name",
                prefix: Padding(
                  padding: const EdgeInsets.all(10.0),
                  child: SvgPicture.asset(
                    imageAssets.user,
                    color: HexColor(AppTheme.secondaryColorString!),
                  ),
                ),
                sufix: const SizedBox(),
                textEditingController: _lastNameController,
                inputType: TextInputType.name,
                isObsecure: false,
                validator:
                    InputValidator.required(message: 'Last Name is required!')!,
              ),
              const SizedBox(height: 30),
              CustomTextField(
                hintText: "Email",
                prefix: Padding(
                  padding: const EdgeInsets.all(10.0),
                  child: SvgPicture.asset(
                    imageAssets.email,
                    color: HexColor(AppTheme.secondaryColorString!),
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
                    color: HexColor(AppTheme.secondaryColorString!),
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
                isObsecure: isHidden,
                validator: InputValidator.multiple([
                  InputValidator.required(message: 'Password is required!')!,
                  InputValidator.password()!,
                ]),
              ),
              const SizedBox(height: 30),
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Checkbox(
                    visualDensity: VisualDensity.compact,
                    value: isCheck,
                    onChanged: (value) {
                      setState(() {
                        isCheck = value!;
                      });
                    },
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          "I certify that I am 18 years of age or older,",
                          style: Theme.of(context)
                              .textTheme
                              .bodyMedium!
                              .copyWith(
                                fontSize: 14,
                                fontWeight: FontWeight.w400,
                                color: HexColor(AppTheme.secondaryColorString!),
                              ),
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            Text(
                              "and I agree to the ",
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyMedium!
                                  .copyWith(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w400,
                                    color: HexColor(
                                        AppTheme.secondaryColorString!),
                                  ),
                            ),
                            Text(
                              "User Agreement ",
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyMedium!
                                  .copyWith(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w400,
                                    color:
                                        HexColor(AppTheme.primaryColorString!),
                                  ),
                            ),
                            Text(
                              "and",
                              style: Theme.of(context)
                                  .textTheme
                                  .bodyMedium!
                                  .copyWith(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w400,
                                    color: HexColor(
                                        AppTheme.secondaryColorString!),
                                  ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          "Privacy Policy",
                          style: Theme.of(context)
                              .textTheme
                              .bodyMedium!
                              .copyWith(
                                fontSize: 14,
                                fontWeight: FontWeight.w400,
                                color: HexColor(AppTheme.primaryColorString!),
                              ),
                        ),
                      ],
                    ),
                  )
                ],
              ),
              const SizedBox(height: 30),
              CustomButton(
                text: isLoading ? "Wait" : "Sign Up",
                onTap: submitter,
              ),
              const SizedBox(height: 20),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Future<void> onSubmit() async {
    if (!isCheck) {
      AppSnackBar.showSnackbar("Please agree to the terms and conditions");
      return;
    }
    print("onSubmit");
    final data = SignUpModel(
      email: _emailController.text,
      password: _passwordController.text,
      firstName: _firstNameController.text,
      lastName: _lastNameController.text,
    );
    print("data: $data");

    final result = await performNetworkOperation(
        context, () => ref.read(signupProvider.notifier).signUp(data));
    if (result != null) {
      if (!mounted) return;
      secureStorage.saveAccessKey(result.accessToken);
      AppSnackBar.showSnackbar('Sign Up Success!');
      AppNavigation.pushAndRemoveUntil(const HomeView());

    }
  }
}
