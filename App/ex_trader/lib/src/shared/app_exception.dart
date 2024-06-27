import 'package:dio/dio.dart';

class AppException {
  AppException({required this.title, required this.error});

  final String title;
  final String error;

  factory AppException.withError(dynamic e) {
    var t = '';
    var err = e.toString();
    if (e is DioException) {
      if (e.response != null) {
        if (e.response!.statusCode == 400) {
          t = 'Invalid User Data!';
          err = 'User with this email already exists!';
        }
      }
    }
    return AppException(error: err, title: t);
  }
}
