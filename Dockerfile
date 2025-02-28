FROM node:20-alpine

WORKDIR /app

RUN npm install 

COPY package.json 

RUN pnpm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
