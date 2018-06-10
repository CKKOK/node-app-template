import React from 'react';
import ReactDOM from 'react-dom';
import Carousel from './Components/Carousel/carousel';

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
        <Carousel />
      </div>
    )
  }
};

ReactDOM.render(
  <Root />,
  document.getElementById('app')
);

module.hot.accept();