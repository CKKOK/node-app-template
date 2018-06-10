import React from 'react';
import './carousel.css';

class CarouselItem extends React.Component {
    constructor() {
        super();
    }

    render() {
        return(
            <div className='carousel-item'>
                {this.props.picture}
            </div>
        )
    }
}

export default class Carousel extends React.Component {
    constructor(){
        super();
        this.state = {
            pictures: ["meh", "muh", "huh"]
        }
    };

    render() {
        const stuff = this.state.pictures.map(url => <CarouselItem picture={url} />);
        return(
            <div className='carousel'>
                {stuff}
                <div className='carousel-prev'>
                    &lt;
                </div>
                <div className='carousel-next'>
                    &gt;
                </div>
            </div>
        )
    }
}