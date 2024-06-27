


import 'package:freezed_annotation/freezed_annotation.dart';

part 'auth_response_dto.freezed.dart';
part 'auth_response_dto.g.dart';

@Freezed(fromJson: true, toJson: false)
class AuthResponseDto with _$AuthResponseDto {
  factory AuthResponseDto({
    required String accessToken,
    required String refreshToken,
    String? message,
    String? accessTokenUpdatedAt,
    UserDto? user,
  }) = _AuthResponseDto;

  factory AuthResponseDto.fromJson(Map<String, dynamic> json) =>
      _$AuthResponseDtoFromJson(json);
}

@Freezed(fromJson: true, toJson: false)
class UserDto with _$UserDto {
  factory UserDto({
    required String id,
    @JsonKey(name: "first_name") required String firstName,
    @JsonKey(name: "last_name") required String lastName,
    required String email,
  }) = _UserDto;

  factory UserDto.fromJson(Map<String, dynamic> json) => _$UserDtoFromJson(json);
}