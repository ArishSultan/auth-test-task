import 'package:dio/dio.dart';
import 'package:ex_trader/src/core/auth/domain/models/auth_response.dart';
import 'package:ex_trader/src/core/auth/domain/models/sign_up.dart';
import 'package:ex_trader/src/core/auth/domain/repositories/auth_repository.dart';
import 'package:ex_trader/src/shared/app_exception.dart';
import 'package:ex_trader/src/shared/states/app_loading_state.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

part 'sign_up_provider.g.dart';

@riverpod
class Signup extends _$Signup {
  @override
  AppLoadingState build() => const AppLoadingState();

  Future<AuthResponseModel> signUp(SignUpModel request) async {
    try {
      state = const AppLoadingState.loading();
      final result = await ref.read(authRepository).signUp(request);
      state = const AppLoadingState();
      return result;
    } catch (e) {
      state = const AppLoadingState();
      if (e is DioException) {
        if (e.response?.statusCode == 400) {
          throw AppException(
            title: 'Error',
            error: 'User with this email already exists',
          );
        }
      }
      rethrow;
    }
  }
}
