install:
	python -m pip install -r requirements.txt

generate-assets:
	python -m src.data_generation.generate_assets

generate-telemetry:
	python -m src.data_generation.generate_telemetry

inject-attacks:
	python -m src.data_generation.inject_attack_scenarios

run-pipeline:
	python -m src.pipeline.run_all

test:
	python -m pytest

lint:
	python -m ruff check .

format:
	python -m ruff check . --fix

dashboard:
	streamlit run src/dashboard/app.py

api:
	uvicorn src.api.main:app --reload

docker-up:
	docker compose up --build

docker-down:
	docker compose down

