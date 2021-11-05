# lext
Length Extension Attack-tool

SHA1, SHA256, SHA224


```console
git clone https://github.com/mumubebe/lext.git
cd lext/
```

Run as module:
```console
$ python3 -m lext \
>     --data 'count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo' \
>     --inject '&waffle=liege' \
>     --signature '6d5f807e23db210bc254a28be2d6759a0f5f5d99' \
>     --secret_length 14 \
>     --method 'sha1'
> 
b'count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02(&waffle=liege'
0e41270260895979317fff3898ab85668953aaa2

```
or 
```python
>>> from lext import lext
>>> inj, sig = lext(
...     data=b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo",
...     inject=b"&waffle=liege",
...     signature="6d5f807e23db210bc254a28be2d6759a0f5f5d99",
...     secret_length=14,
...     method="sha1"
... )
>>> print(sig)
0e41270260895979317fff3898ab85668953aaa2
>>> print(inj)
b'count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02(&waffle=liege'
```

About
```console
usage: __main__.py [-h] [-m {sha1,sha256,sha224}] -d DATA -i INJECT -s SIGNATURE -l SECRET_LENGTH
                   [--no-signature] [--no-outputdata]

Length Extension Attack-tool

optional arguments:
  -h, --help            show this help message and exit
  -m {sha1,sha256,sha224}, --method {sha1,sha256,sha224}
                        Hash method
  -d DATA, --data DATA  The original data known message from server. This data is prepend with a hidden secret
                        unknown to client.
  -i INJECT, --inject INJECT
                        Additional message to append to the original data
  -s SIGNATURE, --signature SIGNATURE
                        Signature of original data
  -l SECRET_LENGTH, --secret_length SECRET_LENGTH
                        Length of the hidden secret that is hidden from client
  --no-signature        Ignore output return of signature
  --no-outputdata       Ignore output return of new data message
```
