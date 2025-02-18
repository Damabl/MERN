# Используем официальный образ Node.js
FROM node:16 AS build

# Устанавливаем Node.js и другие зависимости
WORKDIR /app

# Копируем package.json и package-lock.json (или yarn.lock, если используете Yarn)
COPY package.json package-lock.json ./

# Устанавливаем все зависимости (включая ESLint и другие dev-зависимости)
RUN npm install
# Если у вас есть dev-зависимости ESLint, убедитесь, что они указаны в package.json

# Копируем оставшиеся файлы проекта
COPY . .

# Строим приложение
RUN npm run build

# Используем более легкий образ для production
FROM nginx:alpine

# Копируем собранное приложение в директорию Nginx
COPY --from=build /app/build /usr/share/nginx/html

# Открываем порт для доступа к приложению
EXPOSE 80

# Запускаем Nginx
CMD ["nginx", "-g", "daemon off;"]
