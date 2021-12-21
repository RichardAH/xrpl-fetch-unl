# XRPL-Fetch-UNL

Fetch and validate a validator list from a validator list site

## Install
```
npm install xrpl-fetch-unl
```

## Usage:

```js
const xf = require('xrpl-fetch-unl');
xf.fetch_validated_unl('https://vl.xrplf.org').then(unl => 
{
    console.log(unl);

}).catch(e => 
{
    console.log("error", e);

});
```
