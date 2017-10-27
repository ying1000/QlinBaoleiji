CXXFLAGS = -g -O2 -Wall 
INCLUDE = -I/opt/freesvr/sql/include
LIB = -L/opt/freesvr/sql/lib/ -lmysqlclient
SRCS = $(wildcard *.cpp)
OBJS = $(patsubst %.cpp, %.o, $(SRCS))

findip: $(OBJS)
	g++ -o $@ $(OBJS) $(CXXFLAGS) $(LIB)
$(OBJS): $(SRCS)
	g++ -c -Wall $(SRCS) $(CXXFLAGS) $(INCLUDE)

.PHONY: clean

clean:
	rm -rf $(OBJS) findip
	
						 

