# Simple BGP Router
**made by Vadym Matviichuck and Oleksandr Litus**

### High level approach 
* First, we implemented correct argument parsing for the program to 
    correctly start up.
* Then, we started by correctly receiving and parsing messages on a port
* After that, we added parallelism to the router to handle multiple ports
    at once, and mutex syncronization to prevent data races
* Next, we started implementing the forwarding table, trying different
    data structures the choose the best one.
* Lastly, we added the correct data message forwarding and table dumps.

Update for second part of the project:
* We started by implementing basic revoke.
* Next, we added no_route handling and all connected checks.
* Then, we added route choosing logic for data packages.
* Also, we implemented correct message forwarding depending on neighbor's type.
* Lastly, we implemented the aggregation and disaggregation of routes.
* Did *A LOT* of refactoring.

### Challanges
We spent a lot of time choosing data strctures to use for this project.
After a lot of trial and error, we settled to just have a list since it 
has correct functionality and semantics for the contraints of the program.
We also spent quite some time with debugging the error messages that we 
received from the server since they do not have any clues inside them other 
than the fact it was invalid.
--
Major challenge when we started doing the 'advanced' version was that
our editor, VS Code, decided to erase table.rb's content, while leaving
the file and us with no code that does revoke/update.¯\_(ツ)_/¯
Also, coalescing bitwise logic was a little annoying to figure out and 
implement because the ruby and ipaddr library are outdated (big sad).
Another major challenge was Ruby. Because it is a dynamic language,
we lost a lot of time debugging why some things just stopped working or
trying to understand what wrong with code (when there is just a typo).

### Testing
We ran the program against the provided simulator only, since it tests the 
functionality instead of full resilience against malicious actors in the 
network. 
