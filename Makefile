build-docker:
	docker build -t habits_builder .
	docker run --detach --name builder habits_builder
	docker cp builder:/source/dist/ ./dist
	docker rm builder

ci-build:
	npm add @chouqueth/gleam
	npm install
	npx vite build