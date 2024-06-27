library client;

import 'dart:io';
import 'dart:math' as math;

import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:ex_trader/src/const/consts.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';


part 'interceptors.dart';
part 'pretty_dio_logger.dart';

final client = Provider<Dio>((ref) {
  const timeOut = Duration(seconds: 120000);
  return Dio(
    BaseOptions(
      headers: {"Content-Type": "application/json"},
      baseUrl: kBaseUrl,
      // requestEncoder: (request, options) {

      // },
      connectTimeout: timeOut,
      receiveTimeout: timeOut,
    ),
  )
    ..interceptors.addAll([
      AuthorizationInterceptor(ref),
      if (kDebugMode)
        PrettyDioLogger(
          requestBody: true,
          requestHeader: true,
        ),
    ])
    ..httpClientAdapter = CustomClientAdapter(ref);
});

class CustomClientAdapter extends IOHttpClientAdapter {
  final Ref ref;

  CustomClientAdapter(this.ref);

  @override
  Future<ResponseBody> fetch(RequestOptions options,
      Stream<Uint8List>? requestStream, Future<void>? cancelFuture) async {
    // final token = await ref.read(authRepositoryProvider).accessToken();
    // if (token != null) {
    //   options.headers[HttpHeaders.authorizationHeader] = 'Bearer $token';
    //   debugPrint('CUSTOM CLIENT ACCESS TOKEN $token');
    // }
    return super.fetch(options, requestStream, cancelFuture);
  }
}
