



import 'package:freezed_annotation/freezed_annotation.dart';

part 'auth_response.freezed.dart';

@freezed
class AuthResponseModel with _$AuthResponseModel {
  factory AuthResponseModel({
    required String accessToken,
    required String refreshToken,
     String? message,
     String? accessTokenUpdatedAt,
     UserModel? user,
  }) = _AuthResponseModel;
}

@freezed
class UserModel with _$UserModel {
  factory UserModel({
    required String id,
    required String firstName,
    required String lastName,
    required String email,
  }) = _UserModel;
}