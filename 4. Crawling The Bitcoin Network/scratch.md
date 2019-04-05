
1. get address
2. put it in a "input" queue
3. worker takes it from input queue
4. worker works
5. worker puts result in output queue
6. crawler records results one-by-one

----

1. get address
2. save address into database with a "next connection date"


Main loop

- adds worker inputs if the queue runs low
    - fetch nodes due for a visit
    - put them in a "input" queue
    - worker takes them from input queue
    - worker works
    - worker puts results in output queue
- process worker outputs if there are more than N outputs
    - save them all to database at once
