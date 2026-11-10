use std::collections::HashMap;
use std::path::Path;

use clap::Parser;

use log_analyser::analyze_logs::Analyser;

/// A utility for filtering and analyzing Nginx server logs
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the Nginx log file
    #[arg(short, long)]
    file: String,

    /// Maximum number of rows to process
    #[arg(short = 'n', long, default_value_t = 1000)]
    max_lines: usize,

    /// Filter by HTTP status
    #[arg(short = 's', long)]
    status: Option<u16>,

    /// Filter by HTTP method
    #[arg(short, long)]
    method: Option<String>,

    /// Filter by substring match in the URL path
    #[arg(short = 'p', long)]
    path_pattern: Option<String>,

    /// Filter by IP address or part of an IP address
    #[arg(short, long)]
    ip: Option<String>,

    /// Show only errors (HTTP status >= 400)
    #[arg(long, default_value_t = false)]
    only_errors: bool,

    /// Show only successful requests (HTTP status < 400)
    #[arg(long, default_value_t = false)]
    only_success: bool,

    /// Searching for an arbitrary string throughout an entire log entry
    #[arg(short = 'q', long)]
    search: Option<String>,
}

fn main() {
    // парсинг аргументов командной строки
    let args = Args::parse();

    // проверка, существует ли файл перед запуском анализатора
    if !Path::new(&args.file).exists() {
        eprintln!("Ошибка: Файл '{}' не найден.", args.file);
        std::process::exit(1);
    }

    // проверяем, есть ли хотя бы один фильтр
    let has_filters = args.status.is_some()
        || args.method.is_some()
        || args.path_pattern.is_some()
        || args.ip.is_some()
        || args.only_errors
        || args.only_success;

    // инициализируем мою библиотеку Analyser
    let mut analyser = Analyser::default()
        .lines(args.max_lines)
        .with_filters(has_filters);

    // динамически навешиваем фильтры CLI-флагов
    if let Some(status_code) = args.status {
        analyser = analyser.filter_status(status_code);
    }

    if let Some(method_str) = &args.method {
        analyser = analyser.filter_method(method_str);
    }

    if let Some(path_str) = &args.path_pattern {
        analyser = analyser.filter_path(path_str);
    }

    if let Some(ip_str) = &args.ip {
        analyser = analyser.filter_by_ip(ip_str);
    }

    if args.only_errors {
        analyser = analyser.filter_errors();
    }

    if args.only_success {
        analyser = analyser.filter_success();
    }

    // запуск анализатора логов
    let result = if let Some(search_query) = &args.search {
        analyser.search_by_pattern(&args.file, search_query)
    } else {
        analyser.analyze_logs(&args.file)
    };

    // выводим результаты работы и статистику
    match result {
        Ok(log_iterator) => {
            use colored::*;
            let mut counter = 0;
            let mut success_count = 0;
            let mut error_count = 0;
            let mut ip_frequencies: HashMap<String, usize> = HashMap::new();

            println!("\n{}", "=== [ НАЧАЛО ВЫВОДА ЛОГОВ ] ===".bright_black());
            for entry in log_iterator {
                entry.output();
                counter += 1;

                // считаем успешные запросы и ошибки
                if entry.status() >= 400 {
                    error_count += 1;
                } else {
                    success_count += 1;
                }

                // считаем частоту IP-адресов
                *ip_frequencies.entry(entry.ip().clone()).or_insert(0) += 1;
            }
            println!("{}\n", "=== [ КОНЕЦ ВЫВОДА ЛОГОВ ] ===".bright_black());

            println!("{}", "> ИТОГИ АНАЛИЗА:".bold().bright_green());
            println!(
                "   • Всего обработано строк: {}",
                counter.to_string().bold().bright_yellow()
            );

            if counter > 0 {
                let success_percent = (success_count as f64 / counter as f64) * 100.0;
                let error_percent = (error_count as f64 / counter as f64) * 100.0;

                println!(
                    "   • Статусы ответов:        {} ({:.1}%) | ❌ Ошибки: {} ({:.1}%)",
                    "Успешно".green(),
                    success_percent,
                    "Критично".red(),
                    error_percent
                );
            }

            // вывод активных айпи адресов
            println!("\n{}", "> ТОП-3 АКТИВНЫХ IP-АДРЕСОВ:".bold().bright_cyan());
            if ip_frequencies.is_empty() {
                println!("   Нет данных для отображения.");
            } else {
                let mut ip_vec: Vec<(&String, &usize)> = ip_frequencies.iter().collect();
                // сортируем по убыванию количества запросов
                ip_vec.sort_by(|a, b| b.1.cmp(a.1));

                for (i, (ip, count)) in ip_vec.iter().take(3).enumerate() {
                    println!(
                        "   [{}]. {} — {} {}",
                        i + 1,
                        ip.bright_white(),
                        count.to_string().bold(),
                        "запросов(а)".dimmed()
                    );
                }
            }
            println!();
        }
        Err(err) => {
            use colored::*;
            eprintln!(
                "{} {}",
                "❌ Произошла ошибка при анализе логов:".red().bold(),
                err
            );
            std::process::exit(1);
        }
    }
}
