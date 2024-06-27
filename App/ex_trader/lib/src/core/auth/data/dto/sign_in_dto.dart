// ignore_for_file: unnecessary_overrides

import 'package:freezed_annotation/freezed_annotation.dart';

part 'sign_in_dto.freezed.dart';
part 'sign_in_dto.g.dart';

@Freezed(toJson: true, fromJson: false)
class SignInDto with _$SignInDto {
  factory SignInDto({
    required String email,
    required String password,
  }) = _SignInDto;

  @override
  Map<String, dynamic> toJson() => super.toJson();
}
