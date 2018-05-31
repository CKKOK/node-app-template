import React from 'react';
import ReactDOM from 'react-dom';

const styles = {
  root: {
    height:           '3em',
    width:            '100%',
    backgroundColor:  'blue',
    color:            'white',
    fontSize:         '1.25em',
    textAlign:        'center',
    borderRadius:     '3px',
  }
}

class Root extends React.Component {
  render() {
    return(
      <div className="root" style={styles.root}>
        This is a React Element. <br />
        {someMsg}
      </div>
    )
  }
};

ReactDOM.render(
  <Root />,
  document.getElementById('app')
);

module.hot.accept();