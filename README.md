Dangerous
=========

In today's crazy world of the Internet, untrusted environments are everywhere.
How do you safely send trusted data into the wild? Sign it! Given a key that
you know (and others don't), you can cryptographically sign your data and send
it into the wild. When you get the data back, you can easily check that the
data wasn't changed.

Internally, dangerous uses HMAC and SHA1 for signing by default. You can easily
change the hashing function if sha1 doesn't fit your needs.

Like most random go libraries by random people you find on GitHub, this library
is considered unstable and its API may change at any time. Use at your own
risk.


## Installation

```
go get github.com/aisola/dangerous
```


## Usage

```go
package main

import (
    "fmt"
    "time"

    "github.com/aisola/dangerous"
)

func main() {
    d := dangerous.New("some super secret key")

    // Optionally set time-to-expiration for this instance.
    d.Duration = 30 * 24 * time.Hour

    // Sign your data
    data := signer.Sign("hello world")
    fmt.Println(data)

    // Verify your data, throws an error if invalid in any way.
    message, err := signer.Verify(data)
    if err != nil {
        fmt.Printf("could not verify: %s", err)
    }

    fmt.Println(message)
}
```


## Example Use Cases

* You can serialize and sign a user ID for unsubscribing of newsletters into
    URLs. This way you don’t need to generate one-time tokens and store them
    in the database. Same thing with any kind of activation link for accounts
    and similar things.
* Signed objects can be stored in cookies or other untrusted sources which
    means you don’t need to have sessions stored on the server, which reduces
    the number of necessary database queries.
* Signed information can safely do a roundtrip between server and client in
    general which makes them useful for passing server-side state to a client
    and then back.
