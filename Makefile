.PHONY: deploy clean

deploy:
	./setup.sh up

clean:
	./setup.sh down
