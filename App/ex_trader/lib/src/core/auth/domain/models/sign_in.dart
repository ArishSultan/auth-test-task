import 'package:freezed_annotation/freezed_annotation.dart';

part 'sign_in.freezed.dart';

@freezed
class SignInModel with _$SignInModel {
  factory SignInModel({
    required String email,
    required String password,
  }) = _SignInModel;
}
