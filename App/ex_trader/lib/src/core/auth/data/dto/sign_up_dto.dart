// ignore_for_file: unnecessary_overrides

import 'package:freezed_annotation/freezed_annotation.dart';

part 'sign_up_dto.freezed.dart';
part 'sign_up_dto.g.dart';

@Freezed(toJson: true, fromJson: false)
class SignUpDto with _$SignUpDto {
  factory SignUpDto({
    required String email,
    required String password,
    @JsonKey(name: "first_name") required String firstName,
    @JsonKey(name: "last_name") required String lastName,
  }) = _SignUpDto;

  @override
  Map<String, dynamic> toJson() => super.toJson();
}
