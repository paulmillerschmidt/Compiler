CXXFLAGS+=-std=c++11

obj2exec: obj2exec.cpp obj2exec.h
	$(CXX) $(CXXFLAGS) -o obj2exec obj2exec.cpp -I.

test-ref:
	./tests/check.py ref

test-linker: obj2exec
	./tests/check.py link

test-loader: obj2exec
	./tests/check.py load

test%: obj2exec
	./tests/check.py $@

.PHONY: test-ref test-linker test-loader test%

.PHONY: clean

clean:
	rm -f obj2exec *.o; \
	cd tests/ && $(MAKE) clean
