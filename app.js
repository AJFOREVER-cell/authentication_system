const express = require('express');
const app = express();
const port = 80;
const path = require('path');
const routes = require('./routes/routes.js');
const user = require('./models.js')

app.set('view engine','ejs');
app.set('views',path.join(__dirname,'views'));


app.get('/',routes);

app.post('/register',routes);
app.get('/login',routes);
app.post('/login',routes);
app.get('/success',routes);
app.get('/logout',routes);

app.listen(port,()=>{
    console.log(`Server is running at port ${port} successfully`);
});