import 'package:dio/dio.dart';
import 'package:ex_trader/src/core/auth/data/dto/auth_response_dto.dart';
import 'package:ex_trader/src/core/auth/data/dto/sign_up_dto.dart';
import 'package:retrofit/retrofit.dart';

import '../dto/sign_in_dto.dart';

part 'auth_api.g.dart';

@RestApi()
abstract interface class AuthApi {
  factory AuthApi(Dio client) => _AuthApi(client, baseUrl: '/member/');

  @POST('signup')
  Future<AuthResponseDto> signUp(@Body() SignUpDto signUpDto);

  @POST('signin')
  Future<AuthResponseDto> signIn(@Body() SignInDto signUpDto);
}
