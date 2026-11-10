use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

// вспомогательная функция
fn create_mock_log_file() -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();

    // записываем тестовые строки в правильном формате Nginx access log
    // формат: IP - - [Дата] "Метод Путь HTTP/1.1" Статус Размер
    let log_data = "\
192.168.1.1 - - [10/Nov/2026:12:00:01 +0300] \"GET /index.html HTTP/1.1\" 200 1024
192.168.1.2 - - [10/Nov/2026:12:00:02 +0300] \"POST /api/v1/users HTTP/1.1\" 201 256
192.168.1.1 - - [10/Nov/2026:12:00:03 +0300] \"GET /admin/panel HTTP/1.1\" 403 512
10.0.0.5 - - [10/Nov/2026:12:00:04 +0300] \"GET /missing-page HTTP/1.1\" 404 128
";

    file.write_all(log_data.as_bytes()).unwrap();
    file
}

#[test]
fn test_file_not_found() {
    // проверяем поведение
    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg("non_existent_file.log");

    cmd.assert()
        .failure() // программа должна завершиться с ошибкой (exit code != 0)
        .stderr(predicate::str::contains(
            "Ошибка: Файл 'non_existent_file.log' не найден.",
        ));
}

#[test]
fn test_basic_reading_and_limit() {
    let file = create_mock_log_file();

    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg(file.path()).arg("-n").arg("2"); // ограничиваем чтение 2 строками

    cmd.assert()
        .success()
        // проверяем, что в выводе есть первые две записи
        .stdout(predicate::str::contains("/index.html"))
        .stdout(predicate::str::contains("/api/v1/users"))
        // финальный счетчик
        .stdout(predicate::str::contains(
            "[Успешно] Обработано и выведено записей: 2",
        ));
}

#[test]
fn test_filter_by_status() {
    let file = create_mock_log_file();

    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg(file.path()).arg("-s").arg("404"); // фильтр логов 404

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("/missing-page"))
        .stdout(predicate::str::contains(
            "[Успешно] Обработано и выведено записей: 1",
        ));
}

#[test]
fn test_filter_by_method() {
    let file = create_mock_log_file();

    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg(file.path()).arg("-m").arg("POST"); // метод POST

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("/api/v1/users"))
        .stdout(predicate::str::contains(
            "[Успешно] Обработано и выведено записей: 1",
        ));
}

#[test]
fn test_filter_only_errors() {
    let file = create_mock_log_file();

    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg(file.path()).arg("--only-errors"); // флаг вывода только ошибок (>= 400)

    cmd.assert()
        .success()
        // ошибки в логе — это 403 и 404
        .stdout(predicate::str::contains("status: 403"))
        .stdout(predicate::str::contains("status: 404"))
        .stdout(predicate::str::contains(
            "[Успешно] Обработано и выведено записей: 2",
        ));
}

#[test]
fn test_search_query() {
    let file = create_mock_log_file();

    let mut cmd = Command::cargo_bin("log_analyser").unwrap();
    cmd.arg("--file").arg(file.path()).arg("-q").arg("admin"); // поиск по строке "admin"

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("/admin/panel"))
        .stdout(predicate::str::contains(
            "[Успешно] Обработано и выведено записей: 1",
        ));
}
