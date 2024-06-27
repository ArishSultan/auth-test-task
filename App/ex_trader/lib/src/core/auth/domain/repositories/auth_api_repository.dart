import 'package:dio/dio.dart';
import 'package:ex_trader/src/core/auth/data/api/auth_api.dart';
import 'package:ex_trader/src/core/auth/data/dto/sign_in_dto.dart';
import 'package:ex_trader/src/core/auth/data/dto/sign_up_dto.dart';
import 'package:ex_trader/src/core/auth/domain/models/auth_response.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_in.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_up.dart';

import 'auth_repository.dart';

class AuthApiRepository implements AuthenticationRepository {
  AuthApiRepository(this.client);

  final Dio client;

  @override
  Future<AuthResponseModel> signUp(SignUpModel request) async {
    final res = await AuthApi(client).signUp(SignUpDto(
      email: request.email,
      password: request.password,
      firstName: request.firstName,
      lastName: request.lastName,
    ));

    return AuthResponseModel(
      accessToken: res.accessToken,
      refreshToken: res.refreshToken,
      message: res.message,
    );
  }

  @override
  Future<AuthResponseModel> signIn(SignInModel request) async {
    final res = await AuthApi(client).signIn(SignInDto(
      email: request.email,
      password: request.password,
    ));
    return AuthResponseModel(
      accessToken: res.accessToken,
      refreshToken: res.refreshToken,
      message: res.message,
    );
  }
}
