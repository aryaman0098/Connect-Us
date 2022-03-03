var fileInput = document.getElementById("csv");


readFile = function () {
    var reader = new FileReader();
    reader.onload = function () {
        let array=reader.result.split("\r");

        if(array.length<1){
            // throw error => nothing found, please try different file
            alert("csv file is empty, please use another file");
            return ;
        }
        
        // console.log("HEADER: ",array[0]);

        const emails=[];
        const entryNumbers=[];
        for(let i=0;i<array.length;i++){
            let array_element=array[i].split(",");
            for(let j=0;j<array_element.length;j++){

                let stringWithoutSpace=array_element[j].replace(/ /g,'');
                
                if( checkEntryNo(stringWithoutSpace) ){

                    entryNumbers.push(stringWithoutSpace.toLowerCase());
                
                }
                if( ValidateEmail(array_element[j]) ){
                    
                    emails.push(array_element[j].toLowerCase());
                
                }
            }

        }        


        // for(let i=0;i<emails.length;i++){
        //     addTodo(emails[i]);
        // }

        for(let i=0;i<entryNumbers.length;i++){
            let myEmail=entryNumbers[i]+"@iitjammu.ac.in";
            addTodo(myEmail);
        }


        //  Checking any 
        // for(let i=0;i<emails.length;i++){
        //     let entryNo=emails[i].replace(/ /g,'');
        //     entryNo=entryNo.substring(0,11);
        //     if( !entryNumbers.includes(entryNo) ){
        //         console.log(entryNo);
        //     }
        // }


        // entryNumbers array of entry numbers
        // emails araay of emails


        // Send to Server



    };
    // start reading the file. When it is done, calls the onload event defined above.
    reader.readAsText(fileInput.files[0]);
};

fileInput.addEventListener('change', readFile);

document.querySelector('ul').addEventListener('click', handleClickDelete);
document.getElementById('clearAll').addEventListener('click', handleClearAll);
// document.getElementById('addParticipant').addEventListener('click', handleAddParticipant);


function handleAddParticipant(){
    let addEmails=document.getElementById("add_email");
    let emailText=addEmails.value.replace(/ /g,'');

    if(ValidateEmail(emailText)){
        const emailSplit=emailText.split("@");
        // if(emailSplit[1]==="gmail.com" || emailSplit[1]==="iitjammu.ac.in"){

            addEmails.className="form-control form-control-sm";

            let existingEmailList=document.querySelectorAll('.todo-list-item')
            
            if(existingEmailList.length===0){
                addTodo(emailText);

            }
            
            else{
                const existingEmails=[];
                
                for(let i=0;i<existingEmailList.length;i++){
                    existingEmails.push( (existingEmailList[i].innerText).replace(/ /g,'') );
                }
                
                console.log(existingEmails,emailText);

                if(existingEmails.includes(emailText)){
                    // alert("Email Already Exist in list!");
                                        
                }
                else{
                    addTodo(emailText);
                }
            }

            // =document.querySelectorAll('.todo-list-item')[0].innerText 
        
        
        // }
        // else{


        //     addEmails.className="form-control is-invalid";
        //     alert("Not a gmail or IIT Jammu account!");
        // }
    }
    else{

        addEmails.className="form-control is-invalid";
        // alert("Invalid Email!!");
    }
    
    // validation of text -> alert() if req
    // check existing email list and dont add
    // addTodo(addEmails.value);
}


function handleClearAll(e) {
    fileInput.value="";
    document.querySelector('ul').innerHTML = '';
}

function handleClickDelete(e) {
    if (e.target.name == 'deleteButton')
        deleteTodo(e);
}


function deleteTodo(e) {
    let item = e.target.parentNode;
    
    item.addEventListener('transitionend', function () {
        item.remove(); 
    });

    item.classList.add('todo-list-item-fall');


    // document.querySelectorAll('.todo-list-item')[0].innerText 
    

}

function addTodo(todo) {
    let ul = document.querySelector('ul');
    let li = document.createElement('li');
    li.innerHTML = `
        <span class="todo-item">${todo}</span>
        <button type="button" class="btn-close" aria-label="Close" name="deleteButton" style=" margin-left:5px " ></button>
        
    `;
    li.classList.add('todo-list-item');
    ul.appendChild(li);
}




function checkString(string){
    for(let i=0;i<string.length;i++){
        let char=string[i];
        if( !(char.toLowerCase()!= char.toUpperCase()) ){
            return false;
        }   
    }
    return true;
}

function checkEntryNo(string1) {
    if(string1.length===11){
        // middle 3 are alphabets 
        // first four are digits starting with 20
        // last 4 are also digits then true else false
        let middleElements=string1.substring(4,7);
        if( checkString(middleElements) ){
            if( !isNaN(string1.substring(0,4)) && !isNaN(string1.substring(7,11)) && string1[0]==="2" && string1[1]==="0"){
                return true;
            }
            return false;
        }
        return false;
    }
    return false;
}

function ValidateEmail(inputText)
{
    var mailformat = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
    if(inputText.match(mailformat))
    {
        return true;
    }
    return false;
}



