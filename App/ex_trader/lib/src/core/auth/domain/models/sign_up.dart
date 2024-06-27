import 'package:freezed_annotation/freezed_annotation.dart';

part 'sign_up.freezed.dart';

@freezed
class SignUpModel with _$SignUpModel {
  factory SignUpModel({
    required String email,
    required String password,
    required String firstName,
    required String lastName,
  }) = _SignUpModel;
}
