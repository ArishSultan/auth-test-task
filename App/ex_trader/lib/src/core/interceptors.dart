part of 'client.dart';

class AuthorizationInterceptor extends Interceptor {
  AuthorizationInterceptor(this.ref);

  final ProviderRef ref;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    // final token = ref.read(accessTokenProvider);

    // if (token != null) {
    //   debugPrint('ACCESS TOKEN\n$token');
    //   options.headers[HttpHeaders.authorizationHeader] = 'Bearer $token';
    // }

    super.onRequest(options, handler);
  }

  @override
  Future<void> onError(
    DioException err,
    ErrorInterceptorHandler handler,
  ) async {
    if (err.response?.statusCode == HttpStatus.unauthorized) {
      try {
        // final refresh = ref.refresh(accessTokenProvider);
        debugPrint('401 ERROR \n$err');
        // debugPrint(refresh.toString());
        // await ref.read(accessTokenProvider.notifier).refreshToken();
        // final token = ref.read(accessTokenProvider);

        // if (token == null) {
        //   handler.next(err);
        // }

        final requestOptions = err.response!.requestOptions;
        // requestOptions.headers[HttpHeaders.authorizationHeader] =
        //     'Bearer $token';
        final options = Options(
          method: requestOptions.method,
          headers: requestOptions.headers,
        );
        final dioRefresh = Dio(BaseOptions(
          baseUrl: requestOptions.baseUrl,
          headers: <String, String>{
            HttpHeaders.acceptHeader: 'application/json'
          },
        ));
        final response = await dioRefresh.request<dynamic>(
          requestOptions.path,
          data: requestOptions.data,
          queryParameters: requestOptions.queryParameters,
          options: options,
        );
        return handler.resolve(response);
      } catch (_) {
        debugPrint('REFRESH ERROR :$_');
      }
    }
    handler.next(err);
  }
}
