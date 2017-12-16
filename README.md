Dangerous
=========

In today's crazy world of the Internet, untrusted environments are everywhere. How do you safely send trusted data into
the wild? Sign it! Given a key that you know (and others don't), you can cryptographically sign your data and send it
into the wild. When you get the data back, you can easily check that the data wasn't changed.

Internally, dangerous uses HMAC and SHA265 for signing by default. 


## Installation

```
go get github.com/aisola/dangerous
```

## Example Use Cases


* You can serialize and sign a user ID for unsubscribing of newsletters into URLs. This way you don’t need to generate
    one-time tokens and store them in the database. Same thing with any kind of activation link for accounts and similar
    things.
* Signed objects can be stored in cookies or other untrusted sources which means you don’t need to have sessions stored
    on the server, which reduces the number of necessary database queries.
* Signed information can safely do a roundtrip between server and client in general which makes them useful for passing
    server-side state to a client and then back.
