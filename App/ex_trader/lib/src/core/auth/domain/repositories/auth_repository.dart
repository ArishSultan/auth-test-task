import 'package:ex_trader/src/core/auth/domain/models/auth_response.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_in.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_up.dart';
import 'package:ex_trader/src/core/client.dart';
import 'package:riverpod/riverpod.dart';
import 'auth_api_repository.dart';

abstract interface class AuthenticationRepository {
  Future<AuthResponseModel> signUp(SignUpModel request);

  Future<AuthResponseModel> signIn(SignInModel request);
}

final authRepository = Provider<AuthenticationRepository>(
  (ref) => AuthApiRepository(ref.read(client)),
);
