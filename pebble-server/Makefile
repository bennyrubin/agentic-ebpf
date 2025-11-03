.PHONY: docker-build docker-run docker-dispatch

IMAGE_NAME ?= pebble-server:latest
RESULTS_DIR ?= $(CURDIR)/results
DISPATCH ?= scripts/dispatch_docker_experiments.py

docker-build:
	@docker build -t $(IMAGE_NAME) -f docker/Dockerfile .

docker-run:
	@mkdir -p $(RESULTS_DIR) $(RESULTS_DIR)/work
	@docker run --rm \
		--privileged \
		-v $(RESULTS_DIR):/results \
		-v $(RESULTS_DIR)/work:/opt/work \
		--mount type=bind,src=/sys/fs/bpf,target=/sys/fs/bpf \
		$(IMAGE_NAME) $(ARGS)

docker-dispatch:
	@mkdir -p $(RESULTS_DIR)
	@python3 $(DISPATCH) --image $(IMAGE_NAME) --results-dir $(RESULTS_DIR) $(ARGS)
