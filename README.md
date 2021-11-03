# lext
Length Extension tool


```git
git clone https://github.com/mumubebe/lext.git
cd lext/
```


Run as module:
```
python -m lext --help
```
or 
```python
>>> from lext import lext
>>> inj, sig = lext(
...     data=b"count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo",
...     inject=b"&waffle=liege",
...     signature="6d5f807e23db210bc254a28be2d6759a0f5f5d99",
...     secret_length=14,
... )
>>> print(sig)
0e41270260895979317fff3898ab85668953aaa2
>>> print(inj)
b'count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02(&waffle=liege'
```
