cc -std=c89 -g -o main -DLIBTEST_PATH=\"$(pwd)/libtest.so\" main.c ../memeye/memeye.c -ldl -Wall -Wextra -Wpedantic -ansi
cc -std=c89 -g -o target target.c -Wall -Wextra -Wpedantic -ansi
cc -std=c89 -g -o libtest.so -shared -fPIC libtest.c -Wall -Wextra -Wpedantic -ansi