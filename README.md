# Лабораторна робота 2 - Gradle та Java Collections Framework

Студент: Illia Verezei, група ІМ-42

Gradle-проєкт (Kotlin DSL, Version Catalog) з класом `ua.kpi.comsys.collections.LogAnalyzer` для аналізу логів у Common Log Format.

## Варіант

N = 9 (номер у списку групи), V = 9 mod 3 = **0** - аналізатор логів серверів.

## Реалізація

- `getUniqueIps(List<String>)` - `Set` унікальних IP.
- `getTopIps(List<String>, int)` - `topN` найчастіших IP за спаданням частоти, при рівності - за алфавітом.
- Рядки, що не відповідають CLF (включно з невалідною IPv4 та `null`), ігноруються.
- `null` список або `topN <= 0` - `IllegalArgumentException`.
- Лише `java.util.*`: `HashMap` для підрахунку, `HashSet`, сортування `Comparator`.

## Структура

```
gradle/libs.versions.toml      версії JUnit 5 та JaCoCo
build.gradle.kts
src/main/java/ua/kpi/comsys/collections/LogAnalyzer.java
src/test/java/ua/kpi/comsys/collections/LogAnalyzerTest.java
```

## Запуск

Потрібна JDK 21.

```bash
./gradlew build     # збірка + тести
./gradlew test      # лише тести
```

Звіт покриття: `build/reports/jacoco/test/html/index.html` (100% рядків та гілок).
