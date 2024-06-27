import 'package:dio/dio.dart';
import 'package:ex_trader/src/core/auth/domain/models/auth_response.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_in.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/auth/domain/repositories/auth_repository.dart';
import '../../../../shared/app_exception.dart';
import '../../../../shared/states/app_loading_state.dart';

part 'sign_in_provider.g.dart';

@riverpod
class SignIn extends _$SignIn {
  @override
  AppLoadingState build() => const AppLoadingState();

  Future<AuthResponseModel> signIn(SignInModel request) async {
    try {
      state = const AppLoadingState.loading();
      final result = await ref.read(authRepository).signIn(request);
      state = const AppLoadingState();
      return result;
    } catch (e) {
      state = const AppLoadingState();
      if (e is DioException) {
        if (e.response?.statusCode == 400) {
          throw AppException(
            title: 'Invalid Credentials',
            error: 'Email or password is incorrect!',
          );
        } else if (e.response?.statusCode == 404) {
          throw AppException(
            title: 'Invalid Credentials',
            error: 'Account with this email does not exist',
          );
        }
      }
      rethrow;
    }
  }
}
